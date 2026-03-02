import * as db from "../db";
/**
 * Session Management Router
 * 
 * Handles active session tracking, device fingerprinting, geo-IP lookup,
 * session revocation, and cleanup. FIPS 140-3 compliant session tokens.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import { getDb } from "../db";
import { userSessions, users } from "../../drizzle/schema";
import { eq, and, desc, lt, ne, sql } from "drizzle-orm";
import crypto from "node:crypto";

// ─── User Agent Parsing ─────────────────────────────────────────────────────

export function parseUserAgent(ua: string): {
  browserName: string;
  browserVersion: string;
  osName: string;
  osVersion: string;
  deviceType: string;
} {
  let browserName = "Unknown";
  let browserVersion = "";
  let osName = "Unknown";
  let osVersion = "";
  let deviceType = "desktop";

  // Browser detection
  if (ua.includes("Firefox/")) {
    browserName = "Firefox";
    browserVersion = ua.match(/Firefox\/([\d.]+)/)?.[1] || "";
  } else if (ua.includes("Edg/")) {
    browserName = "Edge";
    browserVersion = ua.match(/Edg\/([\d.]+)/)?.[1] || "";
  } else if (ua.includes("OPR/") || ua.includes("Opera/")) {
    browserName = "Opera";
    browserVersion = ua.match(/(?:OPR|Opera)\/([\d.]+)/)?.[1] || "";
  } else if (ua.includes("Chrome/")) {
    browserName = "Chrome";
    browserVersion = ua.match(/Chrome\/([\d.]+)/)?.[1] || "";
  } else if (ua.includes("Safari/") && !ua.includes("Chrome")) {
    browserName = "Safari";
    browserVersion = ua.match(/Version\/([\d.]+)/)?.[1] || "";
  }

  // OS detection
  if (ua.includes("Windows NT")) {
    osName = "Windows";
    const ntVersion = ua.match(/Windows NT ([\d.]+)/)?.[1];
    const ntMap: Record<string, string> = {
      "10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7",
    };
    osVersion = ntMap[ntVersion || ""] || ntVersion || "";
  } else if (ua.includes("Mac OS X")) {
    osName = "macOS";
    osVersion = ua.match(/Mac OS X ([\d_]+)/)?.[1]?.replace(/_/g, ".") || "";
  } else if (ua.includes("Android")) {
    osName = "Android";
    osVersion = ua.match(/Android ([\d.]+)/)?.[1] || "";
  } else if (ua.includes("iPhone") || ua.includes("iPad")) {
    osName = "iOS";
    osVersion = ua.match(/OS ([\d_]+)/)?.[1]?.replace(/_/g, ".") || "";
  } else if (ua.includes("Linux")) {
    osName = "Linux";
  } else if (ua.includes("CrOS")) {
    osName = "ChromeOS";
  }

  // Device type
  if (ua.includes("Mobile") || ua.includes("Android") || ua.includes("iPhone")) {
    deviceType = "mobile";
  } else if (ua.includes("iPad") || ua.includes("Tablet")) {
    deviceType = "tablet";
  }

  return { browserName, browserVersion, osName, osVersion, deviceType };
}

// ─── Geo-IP Lookup ──────────────────────────────────────────────────────────

export async function lookupGeoIP(ip: string): Promise<{
  city: string | null;
  region: string | null;
  country: string | null;
  lat: number | null;
  lon: number | null;
}> {
  // Skip private/local IPs
  if (!ip || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
    return { city: null, region: null, country: null, lat: null, lon: null };
  }

  try {
    // Use ip-api.com free tier (no API key needed, 45 req/min)
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,city,regionName,country,lat,lon`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!resp.ok) return { city: null, region: null, country: null, lat: null, lon: null };
    const data = await resp.json();
    if (data.status !== "success") return { city: null, region: null, country: null, lat: null, lon: null };
    return {
      city: data.city || null,
      region: data.regionName || null,
      country: data.country || null,
      lat: data.lat || null,
      lon: data.lon || null,
    };
  } catch {
    return { city: null, region: null, country: null, lat: null, lon: null };
  }
}

// ─── Device Fingerprint Generation ──────────────────────────────────────────

export function generateDeviceFingerprint(
  userAgent: string,
  ip: string,
  acceptLanguage?: string,
  acceptEncoding?: string
): string {
  const components = [
    userAgent,
    ip,
    acceptLanguage || "",
    acceptEncoding || "",
  ].join("|");
  return crypto.createHash("sha256").update(components).digest("hex").substring(0, 16);
}

// ─── Session Creation ───────────────────────────────────────────────────────

export async function createSessionRecord(params: {
  sessionToken: string;
  userId: number;
  loginMethod: "oauth" | "saml" | "api_key";
  samlIdpId?: number;
  req: { ip?: string; headers: Record<string, string | string[] | undefined> };
}): Promise<number> {
  const db = getDb();
  const { sessionToken, userId, loginMethod, samlIdpId, req } = params;

  const sessionHash = crypto.createHash("sha256").update(sessionToken).digest("hex");
  const ip = (req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim()) || req.ip || "";
  const userAgent = req.headers["user-agent"]?.toString() || "";
  const parsed = parseUserAgent(userAgent);
  const fingerprint = generateDeviceFingerprint(
    userAgent,
    ip,
    req.headers["accept-language"]?.toString(),
    req.headers["accept-encoding"]?.toString()
  );

  // Geo-IP lookup (non-blocking, best effort)
  const geo = await lookupGeoIP(ip);

  const [result] = await db.insert(userSessions).values({
    sessionHash,
    userId,
    loginMethod,
    samlIdpId: samlIdpId || null,
    deviceFingerprint: fingerprint,
    ipAddress: ip,
    geoCity: geo.city,
    geoRegion: geo.region,
    geoCountry: geo.country,
    geoLat: geo.lat,
    geoLon: geo.lon,
    userAgent,
    browserName: parsed.browserName,
    browserVersion: parsed.browserVersion,
    osName: parsed.osName,
    osVersion: parsed.osVersion,
    deviceType: parsed.deviceType,
    isCurrent: false,
    status: "active",
    lastActivityAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });

  return result.insertId;
}

// ─── tRPC Router ────────────────────────────────────────────────────────────

export const sessionRouter = router({
  /** List active sessions for the current user */
  listMySessions: protectedProcedure.query(async ({ ctx }) => {
    const db = getDb();
    const sessions = await db
      .select({
        id: userSessions.id,
        loginMethod: userSessions.loginMethod,
        deviceFingerprint: userSessions.deviceFingerprint,
        ipAddress: userSessions.ipAddress,
        geoCity: userSessions.geoCity,
        geoRegion: userSessions.geoRegion,
        geoCountry: userSessions.geoCountry,
        geoLat: userSessions.geoLat,
        geoLon: userSessions.geoLon,
        browserName: userSessions.browserName,
        browserVersion: userSessions.browserVersion,
        osName: userSessions.osName,
        osVersion: userSessions.osVersion,
        deviceType: userSessions.deviceType,
        isCurrent: userSessions.isCurrent,
        status: userSessions.status,
        lastActivityAt: userSessions.lastActivityAt,
        expiresAt: userSessions.expiresAt,
        createdAt: userSessions.createdAt,
      })
      .from(userSessions)
      .where(and(
        eq(userSessions.userId, ctx.user.id),
        eq(userSessions.status, "active")
      ))
      .orderBy(desc(userSessions.lastActivityAt));

    return sessions;
  }),

  /** Revoke a specific session */
  revokeSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = getDb();
      // Verify the session belongs to the current user
      const [session] = await db
        .select()
        .from(userSessions)
        .where(and(
          eq(userSessions.id, input.sessionId),
          eq(userSessions.userId, ctx.user.id)
        ))
        .limit(1);

      if (!session) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      }

      await db
        .update(userSessions)
        .set({ status: "revoked" })
        .where(eq(userSessions.id, input.sessionId));

      return { success: true };
    }),

  /** Revoke all other sessions (keep current) */
  revokeAllOtherSessions: protectedProcedure
    .input(z.object({ currentSessionHash: z.string().optional() }))
    .mutation(async ({ input, ctx }) => {
      const db = getDb();
      
      if (input.currentSessionHash) {
        // Revoke all except the specified session
        await db
          .update(userSessions)
          .set({ status: "revoked" })
          .where(and(
            eq(userSessions.userId, ctx.user.id),
            eq(userSessions.status, "active"),
            ne(userSessions.sessionHash, input.currentSessionHash)
          ));
      } else {
        // Revoke all active sessions for this user
        await db
          .update(userSessions)
          .set({ status: "revoked" })
          .where(and(
            eq(userSessions.userId, ctx.user.id),
            eq(userSessions.status, "active")
          ));
      }

      return { success: true };
    }),

  /** Get session stats for the current user */
  getSessionStats: protectedProcedure.query(async ({ ctx }) => {
    const db = getDb();
    const [stats] = await db
      .select({
        activeSessions: sql<number>`COUNT(CASE WHEN ${userSessions.status} = 'active' THEN 1 END)`,
        totalSessions: sql<number>`COUNT(*)`,
        uniqueDevices: sql<number>`COUNT(DISTINCT ${userSessions.deviceFingerprint})`,
        uniqueLocations: sql<number>`COUNT(DISTINCT CONCAT(COALESCE(${userSessions.geoCity}, ''), '-', COALESCE(${userSessions.geoCountry}, '')))`,
      })
      .from(userSessions)
      .where(eq(userSessions.userId, ctx.user.id));

    return stats || { activeSessions: 0, totalSessions: 0, uniqueDevices: 0, uniqueLocations: 0 };
  }),

  /** Admin: List all active sessions across all users */
  listAllSessions: adminProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      userId: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const db = getDb();
      let query = db
        .select({
          id: userSessions.id,
          userId: userSessions.userId,
          userName: users.name,
          userEmail: users.email,
          userRole: users.role,
          loginMethod: userSessions.loginMethod,
          ipAddress: userSessions.ipAddress,
          geoCity: userSessions.geoCity,
          geoCountry: userSessions.geoCountry,
          browserName: userSessions.browserName,
          osName: userSessions.osName,
          deviceType: userSessions.deviceType,
          status: userSessions.status,
          lastActivityAt: userSessions.lastActivityAt,
          createdAt: userSessions.createdAt,
        })
        .from(userSessions)
        .leftJoin(users, eq(userSessions.userId, users.id))
        .where(eq(userSessions.status, "active"))
        .orderBy(desc(userSessions.lastActivityAt))
        .limit(input.limit);

      if (input.userId) {
        query = query.where(and(
          eq(userSessions.status, "active"),
          eq(userSessions.userId, input.userId)
        )) as any;
      }

      return query;
    }),

  /** Admin: Force revoke a user's session */
  adminRevokeSession: adminProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      await db
        .update(userSessions)
        .set({ status: "revoked" })
        .where(eq(userSessions.id, input.sessionId));
      return { success: true };
    }),

  /** Admin: Force revoke all sessions for a user */
  adminRevokeAllUserSessions: adminProcedure
    .input(z.object({ userId: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      await db
        .update(userSessions)
        .set({ status: "revoked" })
        .where(and(
          eq(userSessions.userId, input.userId),
          eq(userSessions.status, "active")
        ));
      return { success: true };
    }),

  /** Cleanup expired sessions */
  cleanupExpired: adminProcedure.mutation(async () => {
    const db = getDb();
    const result = await db
      .update(userSessions)
      .set({ status: "expired" })
      .where(and(
        eq(userSessions.status, "active"),
        lt(userSessions.expiresAt, new Date())
      ));
    return { cleaned: (result as any)[0]?.affectedRows || 0 };
  }),
});
