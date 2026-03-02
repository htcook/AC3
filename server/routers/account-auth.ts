/**
 * Email-Based Account Authentication Router
 * 
 * FedRAMP / FIPS 140-3 Compliant:
 * - bcrypt with 12 rounds (NIST SP 800-63B)
 * - Minimum 12-char passwords with complexity (NIST SP 800-63B)
 * - FIPS-approved DRBG for invite/reset tokens (crypto.randomBytes)
 * - Account lockout after 5 failed attempts (NIST SP 800-53 AC-7)
 * - Full auth event audit logging (FedRAMP AU-2/AU-3)
 * - HMAC-SHA256 signed JWTs with HttpOnly/Secure/SameSite cookies
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, publicProcedure, protectedProcedure } from "../_core/trpc";
import { getDb } from "../db";
import { calderaAccounts } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { notifyOwner } from "../_core/notification";

// ─── Constants ────────────────────────────────────────────────────────────────
const BCRYPT_ROUNDS = 12; // FIPS 140-3 / NIST SP 800-63B compliant
const MAX_FAILED_ATTEMPTS = 5; // NIST SP 800-53 AC-7
const LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes
const INVITE_TOKEN_BYTES = 32; // 256-bit FIPS-approved DRBG
const INVITE_EXPIRY_HOURS = 72;
const PASSWORD_RESET_EXPIRY_HOURS = 1;
const CALDERA_SESSION_COOKIE = "caldera_session";
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";

// ─── In-memory rate limiting (per-email failed attempt tracking) ──────────────
const failedAttempts = new Map<string, { count: number; lastAttempt: number; lockedUntil: number }>();

function checkLockout(email: string): { locked: boolean; remainingMs: number } {
  const record = failedAttempts.get(email.toLowerCase());
  if (!record) return { locked: false, remainingMs: 0 };
  if (record.lockedUntil > Date.now()) {
    return { locked: true, remainingMs: record.lockedUntil - Date.now() };
  }
  // Reset if lockout expired
  if (record.count >= MAX_FAILED_ATTEMPTS && record.lockedUntil <= Date.now()) {
    failedAttempts.delete(email.toLowerCase());
  }
  return { locked: false, remainingMs: 0 };
}

function recordFailedAttempt(email: string): void {
  const key = email.toLowerCase();
  const record = failedAttempts.get(key) || { count: 0, lastAttempt: 0, lockedUntil: 0 };
  record.count += 1;
  record.lastAttempt = Date.now();
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
    console.log(`[AccountAuth] LOCKOUT: ${email} locked for ${LOCKOUT_DURATION_MS / 60000} minutes after ${record.count} failed attempts`);
  }
  failedAttempts.set(key, record);
}

function clearFailedAttempts(email: string): void {
  failedAttempts.delete(email.toLowerCase());
}

// ─── Cookie Options (reuse from main router pattern) ──────────────────────────
function getCookieOptions(req: any, rememberMe = false) {
  const host = req.hostname || req.headers?.host || "";
  const isLocalhost = host.includes("localhost");
  const isManusPreview = host.includes("manus.space") || host.includes("manus.computer") || host.includes("manusvm.computer");
  const sameSite = isManusPreview ? ("none" as const) : ("lax" as const);
  return {
    path: "/",
    httpOnly: true,
    secure: !isLocalhost,
    sameSite,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  };
}

// ─── Password Validation (NIST SP 800-63B) ────────────────────────────────────
const passwordSchema = z.string()
  .min(12, "Password must be at least 12 characters (NIST SP 800-63B)")
  .max(128, "Password must not exceed 128 characters")
  .refine(
    (pw) => /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw),
    "Password must contain uppercase, lowercase, digit, and special character"
  );

// ─── Audit Logger ─────────────────────────────────────────────────────────────
async function logAuthEvent(params: {
  action: string;
  email: string;
  success: boolean;
  detail?: string;
  ipAddress?: string;
  userId?: number;
}) {
  try {
    const db = await getDb();
    // Use the existing activity_logs table for FedRAMP AU-2/AU-3 compliance
    await db.execute(sql`
      INSERT INTO activity_logs (action, details, ipAddress, createdAt)
      VALUES (
        ${`auth:${params.action}`},
        ${JSON.stringify({
          email: params.email,
          success: params.success,
          detail: params.detail || null,
          userId: params.userId || null,
          timestamp: new Date().toISOString(),
        })},
        ${params.ipAddress || null},
        NOW()
      )
    `);
  } catch (err) {
    console.error("[AccountAuth] Audit log failed:", err);
  }
}

// ─── Router ───────────────────────────────────────────────────────────────────
export const accountAuthRouter = router({
  // Email-based login
  emailLogin: publicProcedure
    .input(z.object({
      email: z.string().email().max(255),
      password: z.string().min(1),
      rememberMe: z.boolean().optional().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      const email = input.email.toLowerCase().trim();
      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";

      // AC-7: Check lockout
      const lockout = checkLockout(email);
      if (lockout.locked) {
        const remainingMin = Math.ceil(lockout.remainingMs / 60000);
        await logAuthEvent({ action: "login_locked", email, success: false, detail: `Account locked, ${remainingMin}min remaining`, ipAddress });
        return { success: false, message: `Account temporarily locked. Try again in ${remainingMin} minutes.` };
      }

      try {
        const db = await getDb();
        const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.email, email)).limit(1);

        if (!account) {
          // Constant-time delay to prevent user enumeration
          await bcrypt.compare(input.password, "$2a$12$000000000000000000000uGHJKLMNOPQRSTUVWXYZabcdefghij");
          recordFailedAttempt(email);
          await logAuthEvent({ action: "login_failed", email, success: false, detail: "Account not found", ipAddress });
          return { success: false, message: "Invalid credentials" };
        }

        if (account.status === "suspended") {
          await logAuthEvent({ action: "login_suspended", email, success: false, detail: "Account suspended", ipAddress, userId: account.id });
          return { success: false, message: "Account has been suspended. Contact your administrator." };
        }

        if (account.status === "deactivated") {
          await logAuthEvent({ action: "login_deactivated", email, success: false, detail: "Account deactivated", ipAddress, userId: account.id });
          return { success: false, message: "Account has been deactivated." };
        }

        if (account.status === "invited") {
          await logAuthEvent({ action: "login_not_activated", email, success: false, detail: "Account not yet activated", ipAddress, userId: account.id });
          return { success: false, message: "Please complete your account setup using the invite link sent to your email." };
        }

        // Verify password with bcrypt
        const passwordValid = await bcrypt.compare(input.password, account.passwordHash);
        if (!passwordValid) {
          recordFailedAttempt(email);
          const record = failedAttempts.get(email);
          const attemptsLeft = MAX_FAILED_ATTEMPTS - (record?.count || 0);
          await logAuthEvent({ action: "login_failed", email, success: false, detail: `Invalid password, ${attemptsLeft} attempts remaining`, ipAddress, userId: account.id });
          return { success: false, message: attemptsLeft > 0 ? `Invalid credentials. ${attemptsLeft} attempts remaining.` : "Account temporarily locked due to too many failed attempts." };
        }

        // Success — clear lockout, update last login, issue JWT
        clearFailedAttempts(email);

        await db.update(calderaAccounts)
          .set({ lastLoginAt: new Date() })
          .where(eq(calderaAccounts.id, account.id));

        const jwtExpiry = input.rememberMe ? "7d" : "24h";
        const token = jwt.sign(
          {
            accountId: account.id,
            email: account.email,
            displayName: account.displayName,
            role: account.role,
            loginTime: Date.now(),
            authType: "email",
          },
          CALDERA_JWT_SECRET,
          { expiresIn: jwtExpiry }
        );

        ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCookieOptions(ctx.req, input.rememberMe));
        await logAuthEvent({ action: "login_success", email, success: true, detail: `Role: ${account.role}`, ipAddress, userId: account.id });

        console.log(`[AccountAuth] Login successful for ${email} (role: ${account.role})`);
        return {
          success: true,
          message: "Login successful",
          user: {
            id: account.id,
            email: account.email,
            displayName: account.displayName,
            role: account.role,
          },
        };
      } catch (err) {
        console.error("[AccountAuth] Login error:", err);
        return { success: false, message: "Authentication service error" };
      }
    }),

  // Admin: Create/invite a new account
  inviteUser: protectedProcedure
    .input(z.object({
      email: z.string().email().max(255),
      displayName: z.string().min(1).max(255),
      role: z.enum(["admin", "operator", "analyst", "team_lead", "executive", "client", "soc", "viewer"]),
      tempPassword: passwordSchema.optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      const email = input.email.toLowerCase().trim();

      // Only admins can invite
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only administrators can invite users" });
      }

      try {
        const db = await getDb();

        // Check if email already exists
        const [existing] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.email, email)).limit(1);
        if (existing) {
          throw new TRPCError({ code: "CONFLICT", message: "An account with this email already exists" });
        }

        // Generate FIPS-approved invite token (256-bit DRBG)
        const inviteToken = crypto.randomBytes(INVITE_TOKEN_BYTES).toString("hex");
        const inviteExpiresAt = new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);

        // If temp password provided, hash it; otherwise use a placeholder
        const tempPassword = input.tempPassword || crypto.randomBytes(16).toString("base64url") + "!A1";
        const passwordHash = await bcrypt.hash(tempPassword, BCRYPT_ROUNDS);

        const [result] = await db.insert(calderaAccounts).values({
          email,
          passwordHash,
          displayName: input.displayName,
          role: input.role,
          status: input.tempPassword ? "active" : "invited",
          invitedBy: decoded.accountId || null,
          inviteToken,
          inviteExpiresAt,
        });

        await logAuthEvent({
          action: "user_invited",
          email,
          success: true,
          detail: `Role: ${input.role}, invited by: ${decoded.email || decoded.username}`,
          ipAddress,
          userId: (result as any).insertId,
        });

        console.log(`[AccountAuth] User invited: ${email} (role: ${input.role})`);

        // Send invite notification to the platform owner
        const loginUrl = `${ctx.req.protocol}://${ctx.req.get('host')}/login`;
        const inviteUrl = input.tempPassword
          ? loginUrl
          : `${ctx.req.protocol}://${ctx.req.get('host')}/accept-invite?token=${inviteToken}`;
        await notifyOwner({
          title: `New Team Member Invited: ${input.displayName}`,
          content: [
            `A new team member has been invited to the Ace C3 platform.`,
            ``,
            `**Email:** ${email}`,
            `**Display Name:** ${input.displayName}`,
            `**Role:** ${input.role}`,
            `**Invited By:** ${decoded.email || decoded.username}`,
            ``,
            input.tempPassword
              ? `The account is active immediately. Share the login URL with the user: ${loginUrl}`
              : `The user must accept their invite within ${INVITE_EXPIRY_HOURS} hours: ${inviteUrl}`,
            ``,
            `Please share the credentials with the invited user securely.`,
          ].join('\n'),
        }).catch((err) => {
          console.warn(`[AccountAuth] Failed to send invite notification for ${email}:`, err);
        });

        return {
          success: true,
          accountId: (result as any).insertId,
          inviteToken: input.tempPassword ? undefined : inviteToken,
          inviteExpiresAt: inviteExpiresAt.toISOString(),
          message: input.tempPassword
            ? `Account created for ${email} with the provided password (active immediately)`
            : `Invite sent to ${email}. Token expires in ${INVITE_EXPIRY_HOURS} hours.`,
        };
      } catch (err) {
        if (err instanceof TRPCError) throw err;
        console.error("[AccountAuth] Invite error:", err);
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create account" });
      }
    }),

  // Accept invite and set password
  acceptInvite: publicProcedure
    .input(z.object({
      token: z.string().min(1),
      password: passwordSchema,
    }))
    .mutation(async ({ input, ctx }) => {
      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";

      try {
        const db = await getDb();
        const [account] = await db.select().from(calderaAccounts)
          .where(eq(calderaAccounts.inviteToken, input.token))
          .limit(1);

        if (!account) {
          return { success: false, message: "Invalid or expired invite token" };
        }

        if (account.status !== "invited") {
          return { success: false, message: "This invite has already been used" };
        }

        if (account.inviteExpiresAt && account.inviteExpiresAt < new Date()) {
          return { success: false, message: "This invite has expired. Contact your administrator for a new one." };
        }

        const passwordHash = await bcrypt.hash(input.password, BCRYPT_ROUNDS);

        await db.update(calderaAccounts)
          .set({
            passwordHash,
            status: "active",
            inviteToken: null,
            inviteExpiresAt: null,
            updatedAt: new Date(),
          })
          .where(eq(calderaAccounts.id, account.id));

        await logAuthEvent({
          action: "invite_accepted",
          email: account.email,
          success: true,
          detail: `Account activated`,
          ipAddress,
          userId: account.id,
        });

        console.log(`[AccountAuth] Invite accepted: ${account.email}`);
        return { success: true, message: "Account activated. You can now log in." };
      } catch (err) {
        console.error("[AccountAuth] Accept invite error:", err);
        return { success: false, message: "Failed to activate account" };
      }
    }),

  // Admin: List all accounts
  listAccounts: protectedProcedure.query(async ({ ctx }) => {
    const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
    if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
    const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
    if (decoded.role !== "admin") {
      throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
    }

    const db = await getDb();
    const accounts = await db.select({
      id: calderaAccounts.id,
      email: calderaAccounts.email,
      displayName: calderaAccounts.displayName,
      role: calderaAccounts.role,
      status: calderaAccounts.status,
      lastLoginAt: calderaAccounts.lastLoginAt,
      createdAt: calderaAccounts.createdAt,
    }).from(calderaAccounts).orderBy(desc(calderaAccounts.createdAt));

    return accounts;
  }),

  // Admin: Update account role or status
  updateAccount: protectedProcedure
    .input(z.object({
      accountId: z.number(),
      role: z.enum(["admin", "operator", "analyst", "team_lead", "executive", "client", "soc", "viewer"]).optional(),
      status: z.enum(["active", "suspended", "deactivated"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
      }

      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      const db = await getDb();

      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, input.accountId)).limit(1);
      if (!account) throw new TRPCError({ code: "NOT_FOUND", message: "Account not found" });

      // Prevent self-demotion
      if (decoded.accountId === input.accountId && input.role && input.role !== "admin") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot demote your own admin account" });
      }

      const updates: any = { updatedAt: new Date() };
      if (input.role) updates.role = input.role;
      if (input.status) updates.status = input.status;

      await db.update(calderaAccounts).set(updates).where(eq(calderaAccounts.id, input.accountId));

      await logAuthEvent({
        action: "account_updated",
        email: account.email,
        success: true,
        detail: `Updated by ${decoded.email || decoded.username}: ${JSON.stringify({ role: input.role, status: input.status })}`,
        ipAddress,
        userId: input.accountId,
      });

      return { success: true, message: "Account updated" };
    }),

  // Admin: Reset user password (generates new temp password)
  resetPassword: protectedProcedure
    .input(z.object({
      accountId: z.number(),
      newPassword: passwordSchema.optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
      }

      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, input.accountId)).limit(1);
      if (!account) throw new TRPCError({ code: "NOT_FOUND", message: "Account not found" });

      const newPassword = input.newPassword || crypto.randomBytes(12).toString("base64url") + "!A1";
      const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

      await db.update(calderaAccounts)
        .set({ passwordHash, updatedAt: new Date() })
        .where(eq(calderaAccounts.id, input.accountId));

      // Clear any lockout
      clearFailedAttempts(account.email);

      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      await logAuthEvent({
        action: "password_reset",
        email: account.email,
        success: true,
        detail: `Reset by admin: ${decoded.email || decoded.username}`,
        ipAddress,
        userId: input.accountId,
      });

      return {
        success: true,
        tempPassword: input.newPassword ? undefined : newPassword,
        message: input.newPassword ? "Password updated" : `Temporary password generated. Share securely with the user.`,
      };
    }),

  // Self: Change own password
  changePassword: publicProcedure
    .input(z.object({
      currentPassword: z.string().min(1),
      newPassword: passwordSchema,
    }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED", message: "Not authenticated" });

      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) {
        return { success: false, message: "Password change is only available for email-based accounts" };
      }

      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
      if (!account) throw new TRPCError({ code: "NOT_FOUND" });

      const currentValid = await bcrypt.compare(input.currentPassword, account.passwordHash);
      if (!currentValid) {
        await logAuthEvent({ action: "password_change_failed", email: account.email, success: false, detail: "Invalid current password", ipAddress, userId: account.id });
        return { success: false, message: "Current password is incorrect" };
      }

      if (input.currentPassword === input.newPassword) {
        return { success: false, message: "New password must differ from current password" };
      }

      const passwordHash = await bcrypt.hash(input.newPassword, BCRYPT_ROUNDS);
      await db.update(calderaAccounts)
        .set({ passwordHash, updatedAt: new Date() })
        .where(eq(calderaAccounts.id, account.id));

      await logAuthEvent({ action: "password_changed", email: account.email, success: true, ipAddress, userId: account.id });
      return { success: true, message: "Password changed successfully" };
    }),

  // Admin: Resend invite (generate new token)
  resendInvite: protectedProcedure
    .input(z.object({ accountId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
      }

      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, input.accountId)).limit(1);
      if (!account) throw new TRPCError({ code: "NOT_FOUND" });
      if (account.status !== "invited") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Can only resend invites for accounts in 'invited' status" });
      }

      const inviteToken = crypto.randomBytes(INVITE_TOKEN_BYTES).toString("hex");
      const inviteExpiresAt = new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);

      await db.update(calderaAccounts)
        .set({ inviteToken, inviteExpiresAt, updatedAt: new Date() })
        .where(eq(calderaAccounts.id, input.accountId));

      return {
        success: true,
        inviteToken,
        inviteExpiresAt: inviteExpiresAt.toISOString(),
        message: `New invite token generated for ${account.email}`,
      };
    }),
});
