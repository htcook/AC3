import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import type { User } from "../../drizzle/schema";
import { sdk } from "./sdk";
import jwt from "jsonwebtoken";

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

  // First try Manus OAuth
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    // Authentication is optional for public procedures.
    user = null;
  }

  // Fallback: check caldera_session JWT cookie
  if (!user) {
    try {
      const token = opts.req.cookies?.['caldera_session'];
      if (token) {
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
          username: string;
          role: string;
          loginTime: number;
        };
        // Create a synthetic user object that satisfies the User type
        user = {
          id: -1, // Synthetic ID for Cyber C2-auth users
          openId: `caldera:${decoded.username}`,
          name: decoded.username,
          email: null,
          loginMethod: 'caldera',
          role: decoded.role === 'admin' ? 'admin' : 'user',
          createdAt: new Date(decoded.loginTime),
          updatedAt: new Date(),
          lastSignedIn: new Date(decoded.loginTime),
        } as User;
      }
    } catch (err) {
      // Invalid or expired caldera_session token
      user = null;
    }
  }

  return {
    req: opts.req,
    res: opts.res,
    user,
  };
}
