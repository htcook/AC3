import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const soarConnectorRouter = router({
  listConnectors: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { soarConnectors } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(soarConnectors).orderBy(desc(soarConnectors.createdAt));
  }),
  createConnector: protectedProcedure
    .input(z.object({
      name: z.string(),
      platform: z.enum(["splunk_soar", "cortex_xsoar", "swimlane", "tines", "custom"]),
      webhookUrl: z.string(),
      apiKeyEncrypted: z.string().optional(),
      inboundEnabled: z.boolean().optional(),
      outboundEnabled: z.boolean().optional(),
      eventTypes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { soarConnectors } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(soarConnectors).values({
        ...input,
        createdBy: String(ctx.user.id),
      });
      return { id: result[0].insertId };
    }),
  updateConnector: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      webhookUrl: z.string().optional(),
      isActive: z.boolean().optional(),
      inboundEnabled: z.boolean().optional(),
      outboundEnabled: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { soarConnectors } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { id, ...updates } = input;
      await db.update(soarConnectors).set(updates).where(eq(soarConnectors.id, id));
      return { success: true };
    }),
  deleteConnector: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { soarConnectors } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(soarConnectors).where(eq(soarConnectors.id, input.id));
      return { success: true };
    }),
  testConnector: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { soarConnectors } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const rows = await db.select().from(soarConnectors).where(eq(soarConnectors.id, input.id));
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Connector not found" });
      // Simulate webhook test
      try {
        await fetch(rows[0].webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "test", timestamp: new Date().toISOString() }),
        });
        return { success: true, message: "Test webhook sent successfully" };
      } catch (err: any) {
        return { success: false, message: err.message || "Webhook test failed" };
      }
    }),
  listEvents: protectedProcedure
    .input(z.object({
      connectorId: z.number().optional(),
      direction: z.enum(["inbound", "outbound"]).optional(),
      limit: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { soarEvents } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { and, eq, desc } = await import("drizzle-orm");
      const conditions = [];
      if (input.connectorId) conditions.push(eq(soarEvents.connectorId, input.connectorId));
      if (input.direction) conditions.push(eq(soarEvents.direction, input.direction));
      return db.select().from(soarEvents)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(soarEvents.createdAt))
        .limit(input.limit || 50);
    }),
  sendEvent: protectedProcedure
    .input(z.object({
      connectorId: z.number(),
      eventType: z.string(),
      payload: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { soarEvents } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(soarEvents).values({
        connectorId: input.connectorId,
        eventType: input.eventType,
        payload: input.payload,
        direction: "outbound",
        status: "pending",
      });
      return { eventId: result[0].insertId, status: "queued" };
    }),
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { soarConnectors, soarEvents } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { count } = await import("drizzle-orm");
    const connectorCount = await db.select({ value: count() }).from(soarConnectors);
    const eventCount = await db.select({ value: count() }).from(soarEvents);
    return {
      connectorCount: connectorCount[0].value,
      eventCount: eventCount[0].value,
    };
  }),
});
