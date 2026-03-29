import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import type { User } from "../../drizzle/schema";
import { sdk } from "./sdk";
import jwt from "jsonwebtoken";
import { logSessionEvent, extractRequestInfo } from "../lib/session-activity-logger";

const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

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

  // First try Manus OAuth
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    // Authentication is optional for public procedures.
    user = null;
  }

  // Fallback: check caldera_session JWT cookie
  // Supports both service-account tokens (username-based from auth-core.ts)
  // and email-account tokens (accountId/email-based from account-auth.ts)
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
          type: "session_context_fallback",
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
          role: decoded.role === 'admin' ? 'admin' : 'user',
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
