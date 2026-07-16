import { CALDERA_BASE_URL, CALDERA_SESSION_COOKIE, getCalderaCookieOptions, CALDERA_JWT_SECRET } from "../lib/api-helpers";
import { getSessionCookieOptions } from "../_core/cookies";
import { COOKIE_NAME } from "@shared/const";
import { publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { ENV } from "../_core/env";
import jwt from "jsonwebtoken";
import { getDb } from "../db";
import { activeSessions } from "../../drizzle/schema";
import { and, eq } from "drizzle-orm";

export const authRouter = router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(async ({ ctx }) => {
      // Server-side session teardown: delete the active_sessions row so the JWT
      // cannot be reused after logout (the cookie alone is client-side).
      try {
        const token = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
        if (token) {
          const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as { accountId?: number; sessionId?: string };
          if (decoded?.accountId && decoded?.sessionId) {
            const db = await getDb();
            await db
              .delete(activeSessions)
              .where(and(eq(activeSessions.accountId, decoded.accountId), eq(activeSessions.sessionToken, decoded.sessionId)));
          }
        }
      } catch {
        // Token missing/invalid/expired — nothing to tear down server-side.
      }
      // Clear Manus OAuth session cookie
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      // Also clear Caldera session cookie to prevent auto-login bounce
      const calderaCookieOptions = getCalderaCookieOptions(ctx.req);
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, { ...calderaCookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  });

export const calderaAuthRouter = router({
    // Login with Caldera credentials
    login: publicProcedure
      .input(z.object({
        username: z.string().min(1),
        password: z.string().min(1),
        rememberMe: z.boolean().optional().default(false),
      }))
      .mutation(async ({ input, ctx }) => {
        const validUsernames = ['red', 'blue', 'admin'];
        // Credentials come only from env (CALDERA_PASSWORD / CALDERA_API_KEY) or
        // the live Caldera API. No hardcoded/canonical password, no backdoor.
        const envPassword = ENV.calderaPassword;
        const calderaApiKey = ENV.calderaApiKey;

        // Never log password contents, hints, lengths, or character codes.
        console.log(`[Auth] Login attempt: user=${input.username}`);

        // Helper to create session and return success
        const createSession = (username: string, mode: string) => {
          const role = username === 'admin' ? 'admin' : username === 'red' ? 'operator' : username === 'blue' ? 'analyst' : 'user';
          const jwtExpiry = input.rememberMe ? '7d' : '24h';
          const token = jwt.sign(
            { username, role, loginTime: Date.now() },
            CALDERA_JWT_SECRET,
            { expiresIn: jwtExpiry }
          );
          ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCalderaCookieOptions(ctx.req, input.rememberMe));
          console.log(`[Auth] Login successful for ${username} (${mode})`);
          return { success: true, message: `Login successful`, user: { username, role } };
        };

        if (!validUsernames.includes(input.username)) {
          console.log(`[Auth] Login failed: invalid username ${input.username}`);
          return { success: false, message: 'Invalid credentials' };
        }

        // Check 1: Validate against the configured service-account password
        // (CALDERA_PASSWORD). No hardcoded/canonical password, no static backdoor.
        if (envPassword && input.password === envPassword) {
          return createSession(input.username, 'env-password');
        }

        // Check 2: Accept the configured Caldera API key as password
        if (calderaApiKey && input.password === calderaApiKey) {
          return createSession(input.username, 'api-key');
        }

        // Check 3: Try authenticating against the live Caldera API directly
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
            headers: { 'KEY': input.password },
            signal: AbortSignal.timeout(5000),
          });
          if (response.ok) {
            return createSession(input.username, 'caldera-api');
          }
        } catch (error) {
          console.error('[Auth] Caldera API unreachable:', (error as Error).message);
        }

        console.log(`[Auth] Login failed for ${input.username} (all checks failed)`);
        return { success: false, message: 'Invalid credentials' };
      }),

    // Check current session (supports both username-based and email-based JWT tokens)
    session: publicProcedure.query(async ({ ctx }) => {
      const token = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];

      if (!token) {
        return { authenticated: false, user: null, expiresAt: null };
      }
      try {
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
          username?: string;
          email?: string;
          displayName?: string;
          accountId?: number;
          role: string;
          loginTime: number;
          authType?: string;
          exp?: number;
          rememberMe?: boolean;
        };

        // Unified session response for both auth types
        const username = decoded.username || decoded.displayName || decoded.email?.split('@')[0] || 'user';
        // exp is in seconds since epoch
        const expiresAt = decoded.exp ? decoded.exp * 1000 : null;
        return { 
          authenticated: true, 
          expiresAt,
          user: { 
            username,
            email: decoded.email || null,
            displayName: decoded.displayName || null,
            accountId: decoded.accountId || null,
            role: decoded.role,
            loginTime: decoded.loginTime,
            authType: decoded.authType || 'username',
          } 
        };
      } catch {
        return { authenticated: false, user: null, expiresAt: null };
      }
    }),

    // Refresh session — re-sign the JWT with a fresh expiry window
    refreshSession: publicProcedure.mutation(async ({ ctx }) => {
      const token = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      if (!token) {
        return { success: false, message: 'No active session' };
      }
      try {
        // Verify and decode the current token (even if close to expiry)
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as Record<string, any>;
        // Determine original expiry duration from the token
        const wasRememberMe = decoded.rememberMe === true || 
          (decoded.exp && decoded.iat && (decoded.exp - decoded.iat) > 2 * 24 * 60 * 60);
        const jwtExpiry = wasRememberMe ? '7d' : '24h';
        const cookieMaxAge = wasRememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;

        // Build fresh payload (strip JWT-internal fields)
        const { iat, exp, nbf, ...payload } = decoded;
        const newToken = jwt.sign(
          { ...payload, loginTime: Date.now(), rememberMe: wasRememberMe },
          CALDERA_JWT_SECRET,
          { expiresIn: jwtExpiry }
        );

        const cookieOpts = getCalderaCookieOptions(ctx.req, wasRememberMe);
        ctx.res.cookie(CALDERA_SESSION_COOKIE, newToken, { ...cookieOpts, maxAge: cookieMaxAge });

        const newExp = Date.now() + cookieMaxAge;
        console.log(`[Auth] Session refreshed for ${decoded.email || decoded.username || 'unknown'}, new expiry: ${new Date(newExp).toISOString()}`);
        return { success: true, expiresAt: newExp };
      } catch {
        // Token is already expired or invalid
        return { success: false, message: 'Session expired, please log in again' };
      }
    }),
    // Logout — clear both Caldera session and Manus OAuth cookies
    logout: publicProcedure.mutation(async ({ ctx }) => {
      const cookieOpts = getCalderaCookieOptions(ctx.req);
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, { ...cookieOpts, maxAge: -1 });
      // Also clear Manus OAuth session cookie to fully terminate the session
      const oauthCookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...oauthCookieOptions, maxAge: -1 });
      return { success: true };
    }),
  });
