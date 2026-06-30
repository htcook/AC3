import { TRPCError } from "@trpc/server";
import { protectedProcedure, router, adminProcedure} from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { min, or } from "drizzle-orm";


export const serverRouter = router({
    list: protectedProcedure.query(async () => {
      return db.getServerConfigs();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getServerConfigById(input.id);
      }),

    create: adminProcedure
      .input(z.object({
        name: z.string().min(1),
        ipAddress: z.string().min(1),
        httpsUrl: z.string().optional(),
        httpUrl: z.string().optional(),
        region: z.string().optional(),
        dropletSize: z.string().optional(),
        dropletId: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createServerConfig(input);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: id,
          action: 'server_created',
          details: `Created server: ${input.name}`,
        });
        return { id };
      }),

    updateStatus: adminProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['online', 'offline', 'unknown']),
      }))
      .mutation(async ({ input }) => {
        await db.updateServerStatus(input.id, input.status);
        return { success: true };
      }),

    checkHealth: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const server = await db.getServerConfigById(input.id);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });

        const credentials = await db.getCredentialsByServerId(input.id);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;

        if (!apiKey || !server.httpUrl) {
          await db.updateServerStatus(input.id, 'unknown');
          return { status: 'unknown', message: 'Missing API key or URL' };
        }

        try {
          const response = await fetch(`${server.httpUrl}/api/v2/health`, {
            headers: { 'KEY': apiKey },
            signal: AbortSignal.timeout(5000),
          });

          const status = response.ok ? 'online' : 'offline';
          await db.updateServerStatus(input.id, status);
          return { status, message: response.ok ? 'Server is healthy' : 'Server unreachable' };
        } catch {
          await db.updateServerStatus(input.id, 'offline');
          return { status: 'offline', message: 'Connection failed' };
        }
      }),
  });

export const credentialsRouter = router({
    list: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input, ctx }) => {
        // Only admins can see full credentials
        const creds = await db.getCredentialsByServerId(input.serverId);
        if (ctx.user.role !== 'admin') {
          return creds.map(c => ({
            ...c,
            password: c.password ? '••••••••' : null,
            apiKey: c.apiKey ? '••••••••' : null,
          }));
        }
        return creds;
      }),

    create: adminProcedure
      .input(z.object({
        serverId: z.number(),
        credentialType: z.enum(['admin_login', 'red_api_key', 'blue_api_key', 'ssh_key']),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { encryptServerCredential } = await import("../lib/credential-crypto");
        const encryptedInput = { ...input } as any;
        if (input.password) {
          const enc = encryptServerCredential(input.password);
          encryptedInput.password = JSON.stringify(enc);
        }
        if (input.apiKey) {
          const enc = encryptServerCredential(input.apiKey);
          encryptedInput.apiKey = JSON.stringify(enc);
        }
        await db.createCredential(encryptedInput);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: input.serverId,
          action: 'credential_created',
          details: `Added ${input.credentialType} credential (FIPS encrypted)`,
        });
        return { success: true };
      }),

    update: adminProcedure
      .input(z.object({
        id: z.number(),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        const { encryptServerCredential } = await import("../lib/credential-crypto");
        const encryptedUpdates = { ...updates } as any;
        if (updates.password) {
          const enc = encryptServerCredential(updates.password);
          encryptedUpdates.password = JSON.stringify(enc);
        }
        if (updates.apiKey) {
          const enc = encryptServerCredential(updates.apiKey);
          encryptedUpdates.apiKey = JSON.stringify(enc);
        }
        await db.updateCredential(id, encryptedUpdates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'credential_updated',
          details: `Updated credential ID: ${id} (FIPS encrypted)`,
        });
        return { success: true };
      }),
  });
