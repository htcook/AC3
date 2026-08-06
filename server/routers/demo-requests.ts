import { z } from "zod";
import { publicProcedure, protectedProcedure } from "../_core/trpc";
import { router } from "../_core/trpc";
import { getDb } from "../db";
import { demoRequests } from "../../drizzle/schema";
import { eq, desc, sql, and, like, or } from "drizzle-orm";
import { notifyOwner } from "../_core/notification";
import { TRPCError } from "@trpc/server";

// Simple in-memory rate limiter (per IP, 3 requests per hour)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX = 3;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }
  entry.count++;
  return true;
}

export const demoRequestsRouter = router({
  // Public: Submit a demo request (no auth required)
  submit: publicProcedure
    .input(
      z.object({
        name: z.string().min(2, "Name must be at least 2 characters").max(255),
        email: z.string().email("Please enter a valid email address").max(255),
        organization: z.string().min(2, "Organization must be at least 2 characters").max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10, "Please describe your use case in at least 10 characters").max(2000),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();

      // Rate limiting by IP
      const clientIp = (ctx as any).req?.ip || (ctx as any).req?.headers?.["x-forwarded-for"] || "unknown";
      if (!checkRateLimit(clientIp)) {
        throw new TRPCError({
          code: "TOO_MANY_REQUESTS",
          message: "Too many demo requests. Please try again later.",
        });
      }

      // Check for duplicate email submission within last 24 hours
      const recentSubmission = await db
        .select({ id: demoRequests.id })
        .from(demoRequests)
        .where(
          and(
            eq(demoRequests.email, input.email),
            sql`${demoRequests.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`
          )
        )
        .limit(1);

      if (recentSubmission.length > 0) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "A demo request with this email was already submitted recently. We'll be in touch soon.",
        });
      }

      const userAgent = (ctx as any).req?.headers?.["user-agent"] || null;

      // Insert the demo request
      const [result] = await db.insert(demoRequests).values({
        name: input.name,
        email: input.email,
        organization: input.organization,
        jobTitle: input.jobTitle || null,
        useCase: input.useCase,
        ipAddress: clientIp,
        userAgent: userAgent?.substring(0, 512) || null,
      });

      // Notify owner
      try {
        await notifyOwner({
          title: `New Demo Request: ${input.organization}`,
          content: [
            `**Name:** ${input.name}`,
            input.jobTitle ? `**Title:** ${input.jobTitle}` : null,
            `**Organization:** ${input.organization}`,
            `**Email:** ${input.email}`,
            `**Use Case:** ${input.useCase}`,
            `---`,
            `*Submitted at ${new Date().toISOString()}*`,
          ].filter(Boolean).join("\n"),
        });
      } catch (e) {
        // Don't fail the submission if notification fails
        console.error("[DemoRequests] Failed to notify owner:", e);
      }

      return {
        success: true,
        message: "Thank you! We'll reach out within 1-2 business days to schedule your demo.",
        id: result.insertId,
      };
    }),

  // Protected: List all demo requests (admin only)
  list: protectedProcedure
    .input(
      z.object({
        status: z.enum(["new", "contacted", "scheduled", "completed", "declined", "all"]).default("all"),
        search: z.string().optional(),
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
      }

      const db = await getDb();
      const conditions = [];

      if (input.status !== "all") {
        conditions.push(eq(demoRequests.status, input.status));
      }

      if (input.search) {
        const searchTerm = `%${input.search}%`;
        conditions.push(
          or(
            like(demoRequests.name, searchTerm),
            like(demoRequests.email, searchTerm),
            like(demoRequests.organization, searchTerm)
          )!
        );
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [requests, countResult] = await Promise.all([
        db
          .select()
          .from(demoRequests)
          .where(whereClause)
          .orderBy(desc(demoRequests.createdAt))
          .limit(input.limit)
          .offset(input.offset),
        db
          .select({ count: sql<number>`count(*)` })
          .from(demoRequests)
          .where(whereClause),
      ]);

      return {
        requests,
        total: countResult[0]?.count || 0,
      };
    }),

  // Protected: Update demo request status
  updateStatus: protectedProcedure
    .input(
      z.object({
        id: z.number(),
        status: z.enum(["new", "contacted", "scheduled", "completed", "declined"]),
        notes: z.string().max(2000).optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      if (ctx.user.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
      }

      const db = await getDb();
      await db
        .update(demoRequests)
        .set({
          status: input.status,
          ...(input.notes !== undefined ? { notes: input.notes } : {}),
        })
        .where(eq(demoRequests.id, input.id));

      return { success: true };
    }),

  // Protected: Get stats summary
  stats: protectedProcedure.query(async ({ ctx }) => {
    if (ctx.user.role !== "admin") {
      throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
    }

    const db = await getDb();
    const result = await db
      .select({
        status: demoRequests.status,
        count: sql<number>`count(*)`,
      })
      .from(demoRequests)
      .groupBy(demoRequests.status);

    const stats: Record<string, number> = {
      new: 0,
      contacted: 0,
      scheduled: 0,
      completed: 0,
      declined: 0,
      total: 0,
    };

    for (const row of result) {
      stats[row.status] = row.count;
      stats.total += row.count;
    }

    return stats;
  }),
});
