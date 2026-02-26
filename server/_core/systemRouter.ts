import { z } from "zod";
import { notifyOwner } from "./notification";
import { adminProcedure, publicProcedure, router } from "./trpc";

export const systemRouter = router({
  health: publicProcedure
    .input(
      z.object({
        timestamp: z.number().min(0, "timestamp cannot be negative"),
      })
    )
    .query(() => ({
      ok: true,
    })),

  // ─── Error Incident Reporting ─────────────────────────────────────────────
  reportError: publicProcedure
    .input(
      z.object({
        incidentId: z.string().nullable(),
        scope: z.string().default("global"),
        error: z.object({
          name: z.string(),
          message: z.string(),
          stack: z.string().optional(),
        }),
        componentStack: z.string().optional(),
        url: z.string(),
        userAgent: z.string(),
        timestamp: z.string(),
        viewport: z
          .object({
            width: z.number(),
            height: z.number(),
          })
          .optional(),
      })
    )
    .mutation(async ({ input }) => {
      // Log the incident server-side
      console.error(
        `[Incident ${input.incidentId}] Scope: ${input.scope} | ` +
          `Error: ${input.error.name}: ${input.error.message} | ` +
          `URL: ${input.url} | Time: ${input.timestamp}`
      );

      // Store in database if available
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (db) {
          const { sql } = await import("drizzle-orm");
          await db
            .execute(
              sql`
            INSERT INTO error_incidents (incidentId, scope, errorName, errorMessage, errorStack, componentStack, url, userAgent, timestamp, viewportWidth, viewportHeight, createdAt)
            VALUES (${input.incidentId}, ${input.scope}, ${input.error.name}, ${input.error.message}, ${input.error.stack ?? null}, ${input.componentStack ?? null}, ${input.url}, ${input.userAgent}, ${input.timestamp}, ${input.viewport?.width ?? null}, ${input.viewport?.height ?? null}, ${Date.now()})
          `
            )
            .catch(() => {
              // Table might not exist yet — silently skip DB storage
            });
        }
      } catch {
        // DB not available — incident is still logged to console
      }

      // Notify owner for critical errors (app-root scope = full crash)
      if (input.scope === "app-root") {
        await notifyOwner({
          title: `Critical UI Error: ${input.incidentId}`,
          content: `Scope: ${input.scope}\nError: ${input.error.name}: ${input.error.message}\nURL: ${input.url}\nTime: ${input.timestamp}`,
        }).catch(() => {});
      }

      return { received: true, incidentId: input.incidentId };
    }),

  notifyOwner: adminProcedure
    .input(
      z.object({
        title: z.string().min(1, "title is required"),
        content: z.string().min(1, "content is required"),
      })
    )
    .mutation(async ({ input }) => {
      const delivered = await notifyOwner(input);
      return {
        success: delivered,
      } as const;
    }),
});
