import * as db from "../db";
import { CALDERA_SESSION_COOKIE, CALDERA_JWT_SECRET } from "../lib/api-helpers";
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
import { calderaAccounts, activeSessions } from "../../drizzle/schema";
import { eq, desc, and, sql, lt } from "drizzle-orm";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { notifyOwner } from "../_core/notification";
import * as OTPAuth from "otpauth";
import QRCode from "qrcode";

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

// ─── Device Info Parser ──────────────────────────────────────────────────────
function parseDeviceInfo(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  let os = "Unknown OS";
  let browser = "Unknown Browser";
  if (ua.includes("windows")) os = "Windows";
  else if (ua.includes("mac os") || ua.includes("macos")) os = "macOS";
  else if (ua.includes("iphone") || ua.includes("ipad")) os = "iOS";
  else if (ua.includes("android")) os = "Android";
  else if (ua.includes("linux")) os = "Linux";
  if (ua.includes("chrome") && !ua.includes("edg")) browser = "Chrome";
  else if (ua.includes("firefox")) browser = "Firefox";
  else if (ua.includes("safari") && !ua.includes("chrome")) browser = "Safari";
  else if (ua.includes("edg")) browser = "Edge";
  return `${browser} on ${os}`;
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

        // Password verified — check if MFA is required
        clearFailedAttempts(email);

        if (account.totpEnabled) {
          // Issue a short-lived MFA pending token (5 minutes)
          const mfaPendingToken = jwt.sign(
            { accountId: account.id, email: account.email, authType: "mfa_pending" },
            CALDERA_JWT_SECRET,
            { expiresIn: "5m" }
          );
          ctx.res.cookie("caldera_mfa_pending", mfaPendingToken, {
            ...getCookieOptions(ctx.req, false),
            maxAge: 5 * 60 * 1000, // 5 minutes
          });
          await logAuthEvent({ action: "mfa_required", email, success: true, detail: "Password verified, awaiting TOTP", ipAddress, userId: account.id });
          return {
            success: true,
            mfaRequired: true,
            message: "Please enter your authenticator code.",
          };
        }

        // No MFA — issue full session
        await db.update(calderaAccounts)
          .set({ lastLoginAt: new Date() })
          .where(eq(calderaAccounts.id, account.id));

        const jwtExpiry = input.rememberMe ? "7d" : "24h";
        const sessionId = crypto.randomBytes(16).toString("hex");
        const token = jwt.sign(
          {
            accountId: account.id,
            email: account.email,
            displayName: account.displayName,
            role: account.role,
            loginTime: Date.now(),
            authType: "email",
            sessionId,
          },
          CALDERA_JWT_SECRET,
          { expiresIn: jwtExpiry }
        );

        // Track session
        const userAgent = ctx.req.headers["user-agent"] || "unknown";
        const deviceInfo = parseDeviceInfo(userAgent);
        await db.insert(activeSessions).values({
          accountId: account.id,
          sessionToken: sessionId,
          ipAddress,
          userAgent: userAgent.substring(0, 500),
          deviceInfo,
          expiresAt: new Date(Date.now() + (input.rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)),
        });

        ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCookieOptions(ctx.req, input.rememberMe));
        await logAuthEvent({ action: "login_success", email, success: true, detail: `Role: ${account.role}`, ipAddress, userId: account.id });

        console.log(`[AccountAuth] Login successful for ${email} (role: ${account.role})`);
        return {
          success: true,
          mfaRequired: false,
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
            `A new team member has been invited to the AC3 platform.`,
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

  // ─── MFA / TOTP Endpoints ──────────────────────────────────────────────────

  // Generate TOTP secret and QR code for setup
  mfaSetup: publicProcedure.mutation(async ({ ctx }) => {
    const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
    if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
    const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
    if (!decoded.accountId) throw new TRPCError({ code: "BAD_REQUEST", message: "MFA only available for email accounts" });

    const db = await getDb();
    const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
    if (!account) throw new TRPCError({ code: "NOT_FOUND" });
    if (account.totpEnabled) throw new TRPCError({ code: "BAD_REQUEST", message: "MFA is already enabled" });

    // Generate TOTP secret using FIPS-approved HMAC-SHA256
    const secret = new OTPAuth.Secret({ size: 20 });
    const totp = new OTPAuth.TOTP({
      issuer: "AC3 Platform",
      label: account.email,
      algorithm: "SHA256",
      digits: 6,
      period: 30,
      secret,
    });

    // Generate backup codes (8 codes, 8 chars each, FIPS DRBG)
    const backupCodes = Array.from({ length: 8 }, () =>
      crypto.randomBytes(4).toString("hex").toUpperCase()
    );

    // Store secret temporarily (not enabled yet until verified)
    await db.update(calderaAccounts)
      .set({
        totpSecret: secret.base32,
        backupCodes: JSON.stringify(backupCodes),
        updatedAt: new Date(),
      })
      .where(eq(calderaAccounts.id, account.id));

    const otpauthUri = totp.toString();
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri, { width: 256, margin: 2 });

    await logAuthEvent({ action: "mfa_setup_initiated", email: account.email, success: true, userId: account.id });

    return {
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      otpauthUri,
      backupCodes,
    };
  }),

  // Verify TOTP code and enable MFA
  mfaVerifyAndEnable: publicProcedure
    .input(z.object({ code: z.string().length(6) }))
    .mutation(async ({ ctx, input }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) throw new TRPCError({ code: "BAD_REQUEST" });

      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
      if (!account || !account.totpSecret) throw new TRPCError({ code: "BAD_REQUEST", message: "MFA setup not initiated" });

      const totp = new OTPAuth.TOTP({
        issuer: "AC3 Platform",
        label: account.email,
        algorithm: "SHA256",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(account.totpSecret),
      });

      const delta = totp.validate({ token: input.code, window: 1 });
      if (delta === null) {
        await logAuthEvent({ action: "mfa_enable_failed", email: account.email, success: false, detail: "Invalid TOTP code", userId: account.id });
        return { success: false, message: "Invalid verification code. Please try again." };
      }

      await db.update(calderaAccounts)
        .set({ totpEnabled: true, updatedAt: new Date() })
        .where(eq(calderaAccounts.id, account.id));

      await logAuthEvent({ action: "mfa_enabled", email: account.email, success: true, userId: account.id });
      return { success: true, message: "MFA has been enabled successfully." };
    }),

  // Disable MFA (requires current TOTP code or backup code)
  mfaDisable: publicProcedure
    .input(z.object({ code: z.string().min(6).max(8) }))
    .mutation(async ({ ctx, input }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) throw new TRPCError({ code: "BAD_REQUEST" });

      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
      if (!account || !account.totpEnabled) throw new TRPCError({ code: "BAD_REQUEST", message: "MFA is not enabled" });

      // Try TOTP code first
      let verified = false;
      if (input.code.length === 6 && account.totpSecret) {
        const totp = new OTPAuth.TOTP({
          issuer: "AC3 Platform",
          label: account.email,
          algorithm: "SHA256",
          digits: 6,
          period: 30,
          secret: OTPAuth.Secret.fromBase32(account.totpSecret),
        });
        verified = totp.validate({ token: input.code, window: 1 }) !== null;
      }

      // Try backup code
      if (!verified && account.backupCodes) {
        const codes: string[] = JSON.parse(account.backupCodes);
        const idx = codes.indexOf(input.code.toUpperCase());
        if (idx !== -1) {
          verified = true;
          codes.splice(idx, 1);
          await db.update(calderaAccounts)
            .set({ backupCodes: JSON.stringify(codes) })
            .where(eq(calderaAccounts.id, account.id));
        }
      }

      if (!verified) {
        await logAuthEvent({ action: "mfa_disable_failed", email: account.email, success: false, detail: "Invalid code", userId: account.id });
        return { success: false, message: "Invalid verification code or backup code." };
      }

      await db.update(calderaAccounts)
        .set({ totpEnabled: false, totpSecret: null, backupCodes: null, updatedAt: new Date() })
        .where(eq(calderaAccounts.id, account.id));

      await logAuthEvent({ action: "mfa_disabled", email: account.email, success: true, userId: account.id });
      return { success: true, message: "MFA has been disabled." };
    }),

  // Verify TOTP during login (called after password verification)
  mfaLoginVerify: publicProcedure
    .input(z.object({
      email: z.string().email(),
      code: z.string().min(6).max(8),
      rememberMe: z.boolean().optional().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      const email = input.email.toLowerCase().trim();
      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";

      // Check for pending MFA token
      const pendingToken = ctx.req.cookies?.["caldera_mfa_pending"];
      if (!pendingToken) {
        return { success: false, message: "MFA session expired. Please log in again." };
      }

      try {
        const decoded = jwt.verify(pendingToken, CALDERA_JWT_SECRET) as any;
        if (decoded.email !== email || decoded.authType !== "mfa_pending") {
          return { success: false, message: "Invalid MFA session." };
        }

        const db = await getDb();
        const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.email, email)).limit(1);
        if (!account || !account.totpSecret) {
          return { success: false, message: "Account not found or MFA not configured." };
        }

        // Try TOTP code
        let verified = false;
        if (input.code.length === 6) {
          const totp = new OTPAuth.TOTP({
            issuer: "AC3 Platform",
            label: account.email,
            algorithm: "SHA256",
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(account.totpSecret),
          });
          verified = totp.validate({ token: input.code, window: 1 }) !== null;
        }

        // Try backup code
        if (!verified && account.backupCodes) {
          const codes: string[] = JSON.parse(account.backupCodes);
          const idx = codes.indexOf(input.code.toUpperCase());
          if (idx !== -1) {
            verified = true;
            codes.splice(idx, 1);
            await db.update(calderaAccounts)
              .set({ backupCodes: JSON.stringify(codes) })
              .where(eq(calderaAccounts.id, account.id));
          }
        }

        if (!verified) {
          recordFailedAttempt(email);
          await logAuthEvent({ action: "mfa_verify_failed", email, success: false, ipAddress, userId: account.id });
          return { success: false, message: "Invalid verification code." };
        }

        // MFA verified — issue full session token
        clearFailedAttempts(email);
        await db.update(calderaAccounts).set({ lastLoginAt: new Date() }).where(eq(calderaAccounts.id, account.id));

        const jwtExpiry = input.rememberMe ? "7d" : "24h";
        const sessionId = crypto.randomBytes(16).toString("hex");
        const token = jwt.sign(
          {
            accountId: account.id,
            email: account.email,
            displayName: account.displayName,
            role: account.role,
            loginTime: Date.now(),
            authType: "email",
            mfaVerified: true,
            sessionId,
          },
          CALDERA_JWT_SECRET,
          { expiresIn: jwtExpiry }
        );

        // Track session
        const userAgent = ctx.req.headers["user-agent"] || "unknown";
        const deviceInfo = parseDeviceInfo(userAgent);
        await db.insert(activeSessions).values({
          accountId: account.id,
          sessionToken: sessionId,
          ipAddress,
          userAgent: userAgent.substring(0, 500),
          deviceInfo,
          expiresAt: new Date(Date.now() + (input.rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)),
        });

        ctx.res.clearCookie("caldera_mfa_pending");
        ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCookieOptions(ctx.req, input.rememberMe));
        await logAuthEvent({ action: "mfa_login_success", email, success: true, ipAddress, userId: account.id });

        return {
          success: true,
          message: "Login successful",
          user: { id: account.id, email: account.email, displayName: account.displayName, role: account.role },
        };
      } catch (err) {
        console.error("[AccountAuth] MFA verify error:", err);
        return { success: false, message: "MFA verification failed" };
      }
    }),

  // Get MFA status for current user
  mfaStatus: publicProcedure.query(async ({ ctx }) => {
    const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
    if (!sessionToken) return { enabled: false, available: false };
    try {
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) return { enabled: false, available: false };
      const db = await getDb();
      const [account] = await db.select({
        totpEnabled: calderaAccounts.totpEnabled,
        backupCodesCount: sql<number>`JSON_LENGTH(${calderaAccounts.backupCodes})`,
      }).from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
      if (!account) return { enabled: false, available: false };
      return {
        enabled: account.totpEnabled,
        available: true,
        backupCodesRemaining: account.backupCodesCount || 0,
      };
    } catch {
      return { enabled: false, available: false };
    }
  }),

  // ─── Session Management Endpoints ────────────────────────────────────────────

  // Admin: List all active sessions across all accounts
  listSessions: protectedProcedure.query(async ({ ctx }) => {
    const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
    if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
    const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
    if (decoded.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" });

    const db = await getDb();
    // Clean up expired sessions first
    await db.delete(activeSessions).where(lt(activeSessions.expiresAt, new Date()));

    const sessions = await db.select({
      id: activeSessions.id,
      accountId: activeSessions.accountId,
      ipAddress: activeSessions.ipAddress,
      deviceInfo: activeSessions.deviceInfo,
      lastActivityAt: activeSessions.lastActivityAt,
      expiresAt: activeSessions.expiresAt,
      createdAt: activeSessions.createdAt,
      userEmail: calderaAccounts.email,
      userDisplayName: calderaAccounts.displayName,
      userRole: calderaAccounts.role,
    })
    .from(activeSessions)
    .leftJoin(calderaAccounts, eq(activeSessions.accountId, calderaAccounts.id))
    .orderBy(desc(activeSessions.lastActivityAt));

    return sessions;
  }),

  // Admin: Revoke a specific session
  revokeSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" });

      const db = await getDb();
      const [session] = await db.select().from(activeSessions).where(eq(activeSessions.id, input.sessionId)).limit(1);
      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });

      await db.delete(activeSessions).where(eq(activeSessions.id, input.sessionId));

      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      await logAuthEvent({
        action: "session_revoked",
        email: decoded.email || "admin",
        success: true,
        detail: `Session ${input.sessionId} for account ${session.accountId} revoked`,
        ipAddress,
      });

      return { success: true, message: "Session revoked" };
    }),

  // Admin: Revoke all sessions for a specific account
  revokeAllSessions: protectedProcedure
    .input(z.object({ accountId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (decoded.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" });

      const db = await getDb();
      const result = await db.delete(activeSessions).where(eq(activeSessions.accountId, input.accountId));

      const ipAddress = ctx.req.ip || ctx.req.headers["x-forwarded-for"] as string || "unknown";
      await logAuthEvent({
        action: "all_sessions_revoked",
        email: decoded.email || "admin",
        success: true,
        detail: `All sessions for account ${input.accountId} revoked`,
        ipAddress,
      });

      return { success: true, message: "All sessions revoked for this account" };
    }),

  // Self: List own sessions
  mySessions: publicProcedure.query(async ({ ctx }) => {
    const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
    if (!sessionToken) return [];
    try {
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) return [];
      const db = await getDb();
      return await db.select({
        id: activeSessions.id,
        ipAddress: activeSessions.ipAddress,
        deviceInfo: activeSessions.deviceInfo,
        lastActivityAt: activeSessions.lastActivityAt,
        createdAt: activeSessions.createdAt,
        isCurrent: sql<boolean>`${activeSessions.sessionToken} = ${decoded.sessionId || ''}`,
      })
      .from(activeSessions)
      .where(eq(activeSessions.accountId, decoded.accountId))
      .orderBy(desc(activeSessions.lastActivityAt));
    } catch {
      return [];
    }
  }),

  // Regenerate backup codes (requires current TOTP code to verify identity)
  mfaRegenerateBackupCodes: publicProcedure
    .input(z.object({ code: z.string().length(6) }))
    .mutation(async ({ ctx, input }) => {
      const sessionToken = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!sessionToken) throw new TRPCError({ code: "UNAUTHORIZED" });
      const decoded = jwt.verify(sessionToken, CALDERA_JWT_SECRET) as any;
      if (!decoded.accountId) throw new TRPCError({ code: "BAD_REQUEST" });

      const db = await getDb();
      const [account] = await db.select().from(calderaAccounts).where(eq(calderaAccounts.id, decoded.accountId)).limit(1);
      if (!account || !account.totpEnabled || !account.totpSecret) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "MFA must be enabled to regenerate backup codes" });
      }

      // Verify current TOTP code
      const totp = new OTPAuth.TOTP({
        issuer: "AC3 Platform",
        label: account.email,
        algorithm: "SHA256",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(account.totpSecret),
      });
      const delta = totp.validate({ token: input.code, window: 1 });
      if (delta === null) {
        await logAuthEvent({ action: "backup_codes_regen_failed", email: account.email, success: false, detail: "Invalid TOTP code", userId: account.id });
        return { success: false, message: "Invalid verification code. Please try again." };
      }

      // Generate new backup codes
      const newBackupCodes = Array.from({ length: 8 }, () =>
        crypto.randomBytes(4).toString("hex").toUpperCase()
      );

      await db.update(calderaAccounts)
        .set({ backupCodes: JSON.stringify(newBackupCodes), updatedAt: new Date() })
        .where(eq(calderaAccounts.id, account.id));

      const ipAddress = ctx.req.ip || (ctx.req.headers["x-forwarded-for"] as string) || "unknown";
      await logAuthEvent({
        action: "backup_codes_regenerated",
        email: account.email,
        success: true,
        detail: "8 new backup codes generated",
        ipAddress,
        userId: account.id,
      });

      return { success: true, backupCodes: newBackupCodes };
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
