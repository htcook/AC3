/**
 * Session Recording & Playback Router
 *
 * Persists terminal output to the database during active sessions,
 * providing timestamped playback with timeline scrubbing.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";

// In-memory tracking of active recordings
const activeRecordings = new Map<string, {
  recordingId: number;
  serverId: number;
  sessionId: string;
  startTime: number;
  chunkCount: number;
  totalBytes: number;
  pollInterval?: ReturnType<typeof setInterval>;
}>();

// Helper to build a recording key
function recordingKey(serverId: number, sessionId: string): string {
  return `${serverId}:${sessionId}`;
}

export const sessionRecordingsRouter = router({
  // ─── Start Recording ─────────────────────────────────────────────────────
  startRecording: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      sessionType: z.enum(["shell", "meterpreter"]),
      targetHost: z.string().optional(),
      username: z.string().optional(),
      platform: z.string().optional(),
      viaExploit: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { sessionRecordings } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const dbConn = await getDbRequired();

      const key = recordingKey(input.serverId, input.sessionId);
      if (activeRecordings.has(key)) {
        const existing = activeRecordings.get(key)!;
        return { recordingId: existing.recordingId, alreadyRecording: true };
      }

      // Create recording entry
      const [result] = await dbConn.insert(sessionRecordings).values({
        serverId: input.serverId,
        sessionId: input.sessionId,
        sessionType: input.sessionType,
        targetHost: input.targetHost || null,
        username: input.username || null,
        platform: input.platform || null,
        viaExploit: input.viaExploit || null,
        status: "recording",
        createdBy: ctx.user.openId,
      });

      const recordingId = result.insertId;

      // Track in memory
      activeRecordings.set(key, {
        recordingId,
        serverId: input.serverId,
        sessionId: input.sessionId,
        startTime: Date.now(),
        chunkCount: 0,
        totalBytes: 0,
      });

      // Add system chunk marking recording start
      const { recordingChunks } = await import("../../drizzle/schema");
      await dbConn.insert(recordingChunks).values({
        recordingId,
        chunkIndex: 0,
        chunkType: "system",
        content: `[Recording started at ${new Date().toISOString()}]`,
        timestampMs: 0,
      });

      return { recordingId, alreadyRecording: false };
    }),

  // ─── Append Chunk ────────────────────────────────────────────────────────
  appendChunk: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      content: z.string(),
      chunkType: z.enum(["input", "output", "system"]).default("output"),
    }))
    .mutation(async ({ input }) => {
      const key = recordingKey(input.serverId, input.sessionId);
      const recording = activeRecordings.get(key);
      if (!recording) return { appended: false, reason: "no_active_recording" };

      const { recordingChunks, sessionRecordings } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      recording.chunkCount++;
      recording.totalBytes += Buffer.byteLength(input.content, "utf-8");
      const timestampMs = Date.now() - recording.startTime;

      await dbConn.insert(recordingChunks).values({
        recordingId: recording.recordingId,
        chunkIndex: recording.chunkCount,
        chunkType: input.chunkType,
        content: input.content,
        timestampMs,
      });

      // Update recording stats
      await dbConn.update(sessionRecordings)
        .set({
          totalChunks: recording.chunkCount,
          totalBytes: recording.totalBytes,
          durationMs: timestampMs,
        })
        .where(eq(sessionRecordings.id, recording.recordingId));

      return { appended: true, chunkIndex: recording.chunkCount, timestampMs };
    }),

  // ─── Stop Recording ──────────────────────────────────────────────────────
  stopRecording: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const key = recordingKey(input.serverId, input.sessionId);
      const recording = activeRecordings.get(key);
      if (!recording) throw new TRPCError({ code: "NOT_FOUND", message: "No active recording for this session" });

      const { sessionRecordings, recordingChunks } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const durationMs = Date.now() - recording.startTime;

      // Add system chunk marking recording end
      recording.chunkCount++;
      await dbConn.insert(recordingChunks).values({
        recordingId: recording.recordingId,
        chunkIndex: recording.chunkCount,
        chunkType: "system",
        content: `[Recording stopped at ${new Date().toISOString()}] Duration: ${Math.round(durationMs / 1000)}s`,
        timestampMs: durationMs,
      });

      // Update recording status
      await dbConn.update(sessionRecordings)
        .set({
          status: "completed",
          totalChunks: recording.chunkCount,
          totalBytes: recording.totalBytes,
          durationMs,
          completedAt: new Date(),
        })
        .where(eq(sessionRecordings.id, recording.recordingId));

      if (recording.pollInterval) clearInterval(recording.pollInterval);
      activeRecordings.delete(key);

      return { recordingId: recording.recordingId, durationMs, totalChunks: recording.chunkCount };
    }),

  // ─── List Recordings ─────────────────────────────────────────────────────
  listRecordings: protectedProcedure
    .input(z.object({
      serverId: z.number().optional(),
      status: z.enum(["recording", "completed", "error"]).optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const { sessionRecordings } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq, desc, and, sql } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const conditions: any[] = [];
      if (input.serverId) conditions.push(eq(sessionRecordings.serverId, input.serverId));
      if (input.status) conditions.push(eq(sessionRecordings.status, input.status));

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [items, countResult] = await Promise.all([
        dbConn.select().from(sessionRecordings)
          .where(whereClause)
          .orderBy(desc(sessionRecordings.startedAt))
          .limit(input.limit)
          .offset(input.offset),
        dbConn.select({ count: sql<number>`COUNT(*)` }).from(sessionRecordings).where(whereClause),
      ]);

      return { items, total: countResult[0]?.count || 0 };
    }),

  // ─── Get Recording Detail ────────────────────────────────────────────────
  getRecording: protectedProcedure
    .input(z.object({ recordingId: z.number() }))
    .query(async ({ input }) => {
      const { sessionRecordings } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [recording] = await dbConn.select().from(sessionRecordings)
        .where(eq(sessionRecordings.id, input.recordingId))
        .limit(1);

      if (!recording) throw new TRPCError({ code: "NOT_FOUND", message: "Recording not found" });
      return recording;
    }),

  // ─── Playback (get chunks for replay) ────────────────────────────────────
  getPlaybackData: protectedProcedure
    .input(z.object({
      recordingId: z.number(),
      fromChunk: z.number().min(0).default(0),
      toChunk: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { recordingChunks, sessionRecordings } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq, and, gte, lte, asc } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      // Verify recording exists
      const [recording] = await dbConn.select().from(sessionRecordings)
        .where(eq(sessionRecordings.id, input.recordingId))
        .limit(1);
      if (!recording) throw new TRPCError({ code: "NOT_FOUND", message: "Recording not found" });

      const conditions: any[] = [eq(recordingChunks.recordingId, input.recordingId)];
      conditions.push(gte(recordingChunks.chunkIndex, input.fromChunk));
      if (input.toChunk !== undefined) {
        conditions.push(lte(recordingChunks.chunkIndex, input.toChunk));
      }

      const chunks = await dbConn.select().from(recordingChunks)
        .where(and(...conditions))
        .orderBy(asc(recordingChunks.chunkIndex))
        .limit(1000);

      return {
        recording,
        chunks,
        totalDurationMs: recording.durationMs || 0,
        totalChunks: recording.totalChunks,
      };
    }),

  // ─── Delete Recording ────────────────────────────────────────────────────
  deleteRecording: protectedProcedure
    .input(z.object({ recordingId: z.number() }))
    .mutation(async ({ input }) => {
      const { sessionRecordings, recordingChunks } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      // Delete chunks first, then recording
      await dbConn.delete(recordingChunks).where(eq(recordingChunks.recordingId, input.recordingId));
      await dbConn.delete(sessionRecordings).where(eq(sessionRecordings.id, input.recordingId));

      return { deleted: true };
    }),

  // ─── Active Recording Status ─────────────────────────────────────────────
  getActiveRecordings: protectedProcedure.query(async () => {
    const result: Array<{
      key: string;
      recordingId: number;
      serverId: number;
      sessionId: string;
      durationMs: number;
      chunkCount: number;
      totalBytes: number;
    }> = [];

    for (const [key, rec] of Array.from(activeRecordings.entries())) {
      result.push({
        key,
        recordingId: rec.recordingId,
        serverId: rec.serverId,
        sessionId: rec.sessionId,
        durationMs: Date.now() - rec.startTime,
        chunkCount: rec.chunkCount,
        totalBytes: rec.totalBytes,
      });
    }

    return result;
  }),
});
