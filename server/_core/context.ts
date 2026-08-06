import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import type { User } from "../../drizzle/schema";
import { sdk } from "./sdk";
import jwt from "jsonwebtoken";
import { logSessionEvent, extractRequestInfo } from "../lib/session-activity-logger";

const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || process.env.JWT_SECRET || '';

/**
 * Detect whether this server is running on a Manus-hosted environment.
 * On DigitalOcean (or any non-Manus host), we skip the Manus SDK entirely
 * to avoid a 30-second timeout on every request.
 *
 * Detection: OAUTH_SERVER_URL is only set on Manus-hosted deployments.
 * If it's empty or missing, we're on DO/self-hosted.
 */
const OAUTH_SERVER_URL = process.env.OAUTH_SERVER_URL ?? "";
const IS_MANUS_HOSTED = OAUTH_SERVER_URL.length > 0 && OAUTH_SERVER_URL.includes("manus");

if (!IS_MANUS_HOSTED) {
  console.log("[Auth] Non-Manus deployment detected — Manus SDK auth disabled, using Caldera JWT only");
} else {
  console.log("[Auth] Manus-hosted deployment — dual auth enabled (Manus SDK + Caldera JWT fallback)");
}

export type TrpcContext = {
  req: CreateExpressContextOptions["req"];
  res: CreateExpressContextOptions["res"];
  user: User | null;
};

export async function createContext(
  opts: CreateExpressContextOptions
): Promise<TrpcContext> {
  let user: User | null = null;
  const { ipAddress, userAgent } = extractRequestInfo(opts.req);

  // ═══════════════════════════════════════════════════════════════════════════
  // PATH 1: Manus-hosted — try Manus OAuth SDK first, then Caldera JWT fallback
  // ═══════════════════════════════════════════════════════════════════════════
  if (IS_MANUS_HOSTED) {
    try {
      user = await sdk.authenticateRequest(opts.req);
    } catch (error) {
      // Authentication is optional for public procedures.
      user = null;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PATH 2: Caldera JWT (always checked on DO; fallback on Manus)
  // Supports both service-account tokens (username-based from auth-core.ts)
  // and email-account tokens (accountId/email-based from account-auth.ts)
  // ═══════════════════════════════════════════════════════════════════════════
  if (!user) {
    try {
      const token = opts.req.cookies?.['caldera_session'];
      if (token) {
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
          // Service account fields (auth-core.ts)
          username?: string;
          // Email account fields (account-auth.ts)
          accountId?: number;
          email?: string;
          displayName?: string;
          // Common fields
          role: string;
          loginTime: number;
          authType?: string;
          sessionId?: string;
        };

        // Resolve identity from whichever JWT format was used
        const resolvedName = decoded.username || decoded.displayName || decoded.email?.split('@')[0] || 'user';
        const resolvedId = decoded.accountId ?? -1;
        const resolvedOpenId = decoded.accountId
          ? `caldera-account:${decoded.accountId}`
          : `caldera:${decoded.username || 'unknown'}`;
        const resolvedEmail = decoded.email || null;
        const resolvedLoginMethod = decoded.authType || (decoded.accountId ? 'email' : 'caldera');

        // Log session validation with context fallback
        logSessionEvent({
          type: IS_MANUS_HOSTED ? "session_context_fallback" : "session_validated",
          userId: resolvedId,
          email: resolvedEmail || undefined,
          username: decoded.username,
          loginMethod: resolvedLoginMethod,
          ipAddress,
          userAgent,
          sessionId: decoded.sessionId,
          durationMs: Date.now() - decoded.loginTime,
        });

        // Create a synthetic user object that satisfies the User type
        user = {
          id: resolvedId,
          openId: resolvedOpenId,
          name: resolvedName,
          email: resolvedEmail,
          loginMethod: resolvedLoginMethod,
          // Pass through the actual role from JWT — engagement access guard
          // uses FULL_ACCESS_ROLES (admin, operator, team_lead) for scoping.
          // Previously this flattened all non-admin roles to 'user', breaking
          // operator/team_lead access to all engagements.
          role: (['admin','operator','team_lead','analyst','executive','client','soc','viewer','user'] as const).includes(decoded.role as any)
            ? decoded.role as User['role']
            : 'user',
          createdAt: new Date(decoded.loginTime),
          updatedAt: new Date(),
          lastSignedIn: new Date(decoded.loginTime),
        } as User;
      }
    } catch (err) {
      // Log session errors for debugging
      const token = opts.req.cookies?.['caldera_session'];
      if (token) {
        const isExpired = err instanceof jwt.TokenExpiredError;
        logSessionEvent({
          type: isExpired ? "session_expired" : "session_error",
          ipAddress,
          userAgent,
          detail: isExpired
            ? `Token expired at ${(err as jwt.TokenExpiredError).expiredAt?.toISOString()}`
            : `JWT verification failed: ${(err as Error).message?.substring(0, 200)}`,
        });
      }
      user = null;
    }
  }

  return {
    req: opts.req,
    res: opts.res,
    user,
  };
}
