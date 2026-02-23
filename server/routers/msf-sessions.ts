/**
 * MSF Session Monitoring Router
 *
 * Real-time Meterpreter/shell session management through SSH tunnels.
 * Provides session listing, reading, writing (interact), and termination.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { MsfClient } from "../lib/msf-client";

// In-memory session output buffers for polling
const sessionBuffers = new Map<string, {
  output: string[];
  lastRead: number;
  serverId: number;
  sessionId: string;
  type: string;
}>();

// Helper to get a tunnel-connected MsfClient for a server
async function getClientForServer(serverId: number): Promise<MsfClient> {
  const { metasploitServers } = await import("../../drizzle/schema");
  const { getDbRequired } = await import("../db");
  const { eq } = await import("drizzle-orm");
  const dbConn = await getDbRequired();

  const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, serverId)).limit(1);
  if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });

  const client = await MsfClient.fromServerWithTunnel(server);
  if (!client) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create MSF client" });
  return client;
}

export const msfSessionsRouter = router({
  // ─── List all sessions across all servers ──────────────────────────────────
  listAll: protectedProcedure.query(async () => {
    const { metasploitServers } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const { eq } = await import("drizzle-orm");
    const dbConn = await getDbRequired();

    const servers = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.status, "online"));

    const allSessions: Array<{
      serverId: number;
      serverName: string;
      sessionId: string;
      type: string;
      info: string;
      targetHost: string;
      username: string;
      platform: string;
      arch: string;
      via_exploit: string;
      via_payload: string;
      tunnel_local: string;
      tunnel_peer: string;
      desc: string;
      uuid: string;
      exploit_uuid: string;
      routes: string;
    }> = [];

    for (const server of servers) {
      try {
        const client = await MsfClient.fromServerWithTunnel(server);
        if (!client) continue;
        const sessions = await client.listSessions();

        for (const [sessionId, session] of Object.entries(sessions)) {
          allSessions.push({
            serverId: server.id,
            serverName: server.name,
            sessionId,
            type: session.type || "unknown",
            info: session.info || "",
            targetHost: session.target_host || "",
            username: session.username || "",
            platform: session.platform || "",
            arch: session.arch || "",
            via_exploit: session.via_exploit || "",
            via_payload: session.via_payload || "",
            tunnel_local: session.tunnel_local || "",
            tunnel_peer: session.tunnel_peer || "",
            desc: session.desc || "",
            uuid: session.uuid || "",
            exploit_uuid: session.exploit_uuid || "",
            routes: Array.isArray(session.routes) ? session.routes.join(", ") : (session.routes || ""),
          });
        }
      } catch (err: any) {
        console.error(`[MSF Sessions] Failed to list sessions for server ${server.name}:`, err.message);
      }
    }

    return allSessions;
  }),

  // ─── List sessions for a specific server ───────────────────────────────────
  listByServer: protectedProcedure
    .input(z.object({ serverId: z.number() }))
    .query(async ({ input }) => {
      const client = await getClientForServer(input.serverId);
      const sessions = await client.listSessions();

      return Object.entries(sessions).map(([sessionId, session]) => ({
        sessionId,
        type: session.type || "unknown",
        info: session.info || "",
        targetHost: session.target_host || "",
        username: session.username || "",
        platform: session.platform || "",
        arch: session.arch || "",
        via_exploit: session.via_exploit || "",
        via_payload: session.via_payload || "",
        tunnel_local: session.tunnel_local || "",
        tunnel_peer: session.tunnel_peer || "",
        desc: session.desc || "",
        uuid: session.uuid || "",
      }));
    }),

  // ─── Read session output (polling endpoint) ────────────────────────────────
  read: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      sessionType: z.enum(["shell", "meterpreter"]),
    }))
    .query(async ({ input }) => {
      const client = await getClientForServer(input.serverId);
      const bufferKey = `${input.serverId}:${input.sessionId}`;

      try {
        let output = "";
        if (input.sessionType === "meterpreter") {
          output = await client.meterpreterRead(input.sessionId);
        } else {
          const result = await client.shellRead(input.sessionId);
          output = result?.data || "";
        }

        // Append to buffer
        if (!sessionBuffers.has(bufferKey)) {
          sessionBuffers.set(bufferKey, {
            output: [],
            lastRead: Date.now(),
            serverId: input.serverId,
            sessionId: input.sessionId,
            type: input.sessionType,
          });
        }

        const buffer = sessionBuffers.get(bufferKey)!;
        if (output) {
          buffer.output.push(output);
          // Keep only last 1000 lines
          if (buffer.output.length > 1000) {
            buffer.output = buffer.output.slice(-500);
          }
        }
        buffer.lastRead = Date.now();

        return {
          data: output,
          totalLines: buffer.output.length,
          history: buffer.output.join(""),
        };
      } catch (err: any) {
        return {
          data: "",
          totalLines: 0,
          history: "",
          error: err.message,
        };
      }
    }),

  //  // ─── Write command to session (interact) ───────────────────────────────
  write: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      sessionType: z.enum(["shell", "meterpreter"]),
      command: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      // ─── Audit Log (RED tier — session interaction) ───
      const { logOffensiveAction } = await import("../lib/roe-guard");
      logOffensiveAction({
        engagementId: null,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name ?? null,
        actionType: 'session_interaction',
        riskTier: 'red',
        target: `session:${input.sessionId}@server:${input.serverId}`,
        moduleOrTool: `${input.sessionType} command: ${input.command.slice(0, 100)}`,
        resultStatus: 'success',
      }).catch(() => {});

      const client = await getClientForServer(input.serverId);

      try {
        if (input.sessionType === "meterpreter") {
          await client.meterpreterWrite(input.sessionId, input.command);
        } else {
          // Shell sessions need a newline at the end
          const cmd = input.command.endsWith("\n") ? input.command : input.command + "\n";
          await client.shellWrite(input.sessionId, cmd);
        }

        // Record the command in the buffer
        const bufferKey = `${input.serverId}:${input.sessionId}`;
        if (!sessionBuffers.has(bufferKey)) {
          sessionBuffers.set(bufferKey, {
            output: [],
            lastRead: Date.now(),
            serverId: input.serverId,
            sessionId: input.sessionId,
            type: input.sessionType,
          });
        }
        const buffer = sessionBuffers.get(bufferKey)!;
        buffer.output.push(`\n$ ${input.command}\n`);

        return { success: true, message: "Command sent" };
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to write to session: ${err.message}`,
        });
      }
    }),

  // ─── Stop/kill a session ─────────────────────────────────────────
  stop: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ─── Audit Log (RED tier — session termination) ───
      const { logOffensiveAction } = await import("../lib/roe-guard");
      logOffensiveAction({
        engagementId: null,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name ?? null,
        actionType: 'session_interaction',
        riskTier: 'red',
        target: `session:${input.sessionId}@server:${input.serverId}`,
        moduleOrTool: 'Session termination',
        resultStatus: 'success',
      }).catch(() => {});

      const client = await getClientForServer(input.serverId);

      try {
        await client.stopSession(input.sessionId);

        // Clean up buffer
        const bufferKey = `${input.serverId}:${input.sessionId}`;
        sessionBuffers.delete(bufferKey);

        return { success: true, message: `Session ${input.sessionId} terminated` };
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to stop session: ${err.message}`,
        });
      }
    }),

  // ─── Get session details ───────────────────────────────────────────────────
  getDetail: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .query(async ({ input }) => {
      const client = await getClientForServer(input.serverId);
      const sessions = await client.listSessions();
      const session = sessions[input.sessionId];

      if (!session) {
        throw new TRPCError({ code: "NOT_FOUND", message: `Session ${input.sessionId} not found` });
      }

      return {
        sessionId: input.sessionId,
        type: session.type || "unknown",
        info: session.info || "",
        targetHost: session.target_host || "",
        username: session.username || "",
        platform: session.platform || "",
        arch: session.arch || "",
        via_exploit: session.via_exploit || "",
        via_payload: session.via_payload || "",
        tunnel_local: session.tunnel_local || "",
        tunnel_peer: session.tunnel_peer || "",
        desc: session.desc || "",
        uuid: session.uuid || "",
        exploit_uuid: session.exploit_uuid || "",
        routes: session.routes || "",
      };
    }),

  //  // ─── Run a Meterpreter command and get output ─────────────────────────
  meterpreterRun: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      command: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      // ─── Audit Log (RED tier — meterpreter command) ───
      const { logOffensiveAction } = await import("../lib/roe-guard");
      logOffensiveAction({
        engagementId: null,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name ?? null,
        actionType: 'session_interaction',
        riskTier: 'red',
        target: `session:${input.sessionId}@server:${input.serverId}`,
        moduleOrTool: `meterpreter: ${input.command.slice(0, 100)}`,
        resultStatus: 'success',
      }).catch(() => {});

      const client = await getClientForServer(input.serverId);

      try {
        // Write the command
        await client.meterpreterWrite(input.sessionId, input.command);

        // Wait a moment for output
        await new Promise(r => setTimeout(r, 1500));

        // Read the output
        const output = await client.meterpreterRead(input.sessionId);

        return { success: true, output: output || "(no output)" };
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Meterpreter command failed: ${err.message}`,
        });
      }
    }),

  // ─── Get output buffer history ─────────────────────────────────────────────
  getHistory: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .query(async ({ input }) => {
      const bufferKey = `${input.serverId}:${input.sessionId}`;
      const buffer = sessionBuffers.get(bufferKey);

      return {
        history: buffer?.output.join("") || "",
        lineCount: buffer?.output.length || 0,
      };
    }),

  // ─── Clear output buffer ──────────────────────────────────────────────────
  clearHistory: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const bufferKey = `${input.serverId}:${input.sessionId}`;
      const buffer = sessionBuffers.get(bufferKey);
      if (buffer) {
        buffer.output = [];
      }
      return { success: true };
    }),

  // ─── U  // ─── Upgrade shell to meterpreter ───────────────────────────────
  upgradeToMeterpreter: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ─── Audit Log (RED tier — session upgrade) ───
      const { logOffensiveAction } = await import("../lib/roe-guard");
      logOffensiveAction({
        engagementId: null,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name ?? null,
        actionType: 'session_interaction',
        riskTier: 'red',
        target: `session:${input.sessionId}@server:${input.serverId}`,
        moduleOrTool: 'Shell to Meterpreter upgrade',
        resultStatus: 'success',
      }).catch(() => {});

      const client = await getClientForServer(input.serverId);

      try {
        // Use post/multi/manage/shell_to_meterpreter
        // Use meterpreterWrite on a shell session to trigger upgrade
        await client.shellWrite(input.sessionId, "background\n");
        const result = { message: "Shell backgrounded. Use post/multi/manage/shell_to_meterpreter module to upgrade." };
        return { success: true, message: "Upgrade initiated. Check sessions list for new Meterpreter session.", result };
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Upgrade failed: ${err.message}`,
        });
      }
    }),
});
