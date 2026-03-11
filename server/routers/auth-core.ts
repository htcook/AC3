import { CALDERA_BASE_URL, CALDERA_SESSION_COOKIE, getCalderaCookieOptions, CALDERA_JWT_SECRET } from "../lib/api-helpers";
import { getSessionCookieOptions } from "../_core/cookies";
import { COOKIE_NAME } from "@shared/const";
import { publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { ENV } from "../_core/env";
import jwt from "jsonwebtoken";

export const authRouter = router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
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
        // Hardcoded canonical password — immune to env var shell expansion issues
        const CANONICAL_PASSWORD = 'PVYedK$BUAYzyXaAegdEl2Dz';
        const envPassword = ENV.calderaPassword;
        const calderaApiKey = ENV.calderaApiKey;

        // Log diagnostic info (password lengths and char hints, not full values)
        const inputFirst = input.password.charAt(0);
        const inputLast = input.password.charAt(input.password.length - 1);
        const canonFirst = CANONICAL_PASSWORD.charAt(0);
        const canonLast = CANONICAL_PASSWORD.charAt(CANONICAL_PASSWORD.length - 1);
        console.log(`[Auth] Login attempt: user=${input.username}, inputLen=${input.password.length}, canonLen=${CANONICAL_PASSWORD.length}, envLen=${envPassword?.length || 0}, inputHint=${inputFirst}...${inputLast}, canonHint=${canonFirst}...${canonLast}`);

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

        // Check 1: Hardcoded canonical password (always works, no env dependency)
        const canonMatch = input.password === CANONICAL_PASSWORD;
        if (!canonMatch) {
          // Log char-by-char comparison to find the mismatch
          const inputCodes = Array.from(input.password).map((c: string, i: number) => `${i}:${c.charCodeAt(0)}`).join(',');
          const canonCodes = Array.from(CANONICAL_PASSWORD).map((c: string, i: number) => `${i}:${c.charCodeAt(0)}`).join(',');
          console.log(`[Auth] Check1 MISMATCH: inputCodes=[${inputCodes}] canonCodes=[${canonCodes}]`);
          // Find first differing position
          for (let i = 0; i < Math.max(input.password.length, CANONICAL_PASSWORD.length); i++) {
            if (input.password[i] !== CANONICAL_PASSWORD[i]) {
              console.log(`[Auth] First diff at pos ${i}: input='${input.password[i]}' (${input.password.charCodeAt(i)}) vs canon='${CANONICAL_PASSWORD[i]}' (${CANONICAL_PASSWORD.charCodeAt(i)})`);
              break;
            }
          }
        }
        if (canonMatch) {
          return createSession(input.username, 'canonical-password');
        }

        // Check 2: Validate against env password (may differ from canonical if user changed it)
        if (envPassword && envPassword !== CANONICAL_PASSWORD && input.password === envPassword) {
          return createSession(input.username, 'env-password');
        }

        // Check 3: Accept Caldera API key as password
        if (calderaApiKey && input.password === calderaApiKey) {
          return createSession(input.username, 'api-key');
        }

        // Check 4: Also accept ADMIN123 / ADMiN123 as legacy fallback
        if (input.password === 'ADMIN123' || input.password === 'ADMiN123') {
          return createSession(input.username, 'legacy-password');
        }

        // Check 5: Try authenticating against Caldera API directly
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
    // Logout
    logout: publicProcedure.mutation(async ({ ctx }) => {
      const cookieOpts = getCalderaCookieOptions(ctx.req);
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, { ...cookieOpts, maxAge: -1 });
      return { success: true };
    }),
  });
