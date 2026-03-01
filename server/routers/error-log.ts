/**
 * Error Logging & AI Chat Router
 * Provides:
 *   - Error logging endpoints (client + server)
 *   - Error dashboard queries
 *   - AI chat with platform context (errors, OEM creds, engagement data)
 */
import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { logPlatformError, getRecentErrors, resolveError, getErrorStats, purgeOldErrors, getEngagementList } from "../lib/error-logger";
import { matchCredentialsForTechnology, searchCredentials, seedBuiltinCredentials, BUILTIN_DEFAULT_CREDS } from "../lib/oem-default-creds";
import { invokeLLM } from "../_core/llm";
import { getRoleChatConfig } from "../lib/role-chat-prompts";
import { getRoleContext } from "../lib/role-chat-context";

export const errorLogRouter = router({
  /** Log an error from the client side */
  logClientError: publicProcedure
    .input(z.object({
      source: z.enum(["client", "react_boundary", "unhandled_rejection"]),
      severity: z.enum(["critical", "error", "warning", "info"]).default("error"),
      message: z.string().max(65535),
      stack: z.string().max(1000000).optional(),
      page: z.string().max(512).optional(),
      engagementContext: z.record(z.unknown()).optional(),
      clientMeta: z.record(z.unknown()).optional(),
      autoRecovered: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const id = await logPlatformError({
        ...input,
        userId: ctx.user?.id || null,
      });
      return { logged: !!id, errorId: id };
    }),

  /** Get recent errors for the dashboard — supports engagement-scoped filtering */
  list: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
      source: z.string().optional(),
      severity: z.string().optional(),
      resolved: z.boolean().optional(),
      search: z.string().optional(),
      engagementId: z.number().optional(),
      engagementName: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getRecentErrors(input || {});
    }),

  /** Get error statistics — optionally scoped to an engagement */
  stats: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      engagementName: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getErrorStats(input || {});
    }),

  /** List distinct engagements that have logged errors */
  engagements: protectedProcedure.query(async () => {
    return getEngagementList();
  }),

  /** Resolve or unresolve an error */
  resolve: protectedProcedure
    .input(z.object({
      id: z.number(),
      resolved: z.boolean(),
      note: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      await resolveError(input.id, input.resolved, input.note);
      return { success: true };
    }),

  /** Purge old resolved errors */
  purge: protectedProcedure
    .input(z.object({ olderThanDays: z.number().min(1).default(30) }))
    .mutation(async ({ input }) => {
      const count = await purgeOldErrors(input.olderThanDays);
      return { purged: count };
    }),
});

export const oemCredsRouter = router({
  /** Search default credentials by vendor/product/protocol */
  search: protectedProcedure
    .input(z.object({ query: z.string().min(1) }))
    .query(async ({ input }) => {
      // First check DB, fall back to built-in
      const dbResults = await searchCredentials(input.query);
      if (dbResults.length > 0) return dbResults;
      // Fall back to in-memory search
      const q = input.query.toLowerCase();
      return BUILTIN_DEFAULT_CREDS.filter(c =>
        c.vendor.toLowerCase().includes(q) ||
        c.product.toLowerCase().includes(q) ||
        c.protocol.toLowerCase().includes(q) ||
        c.tags.some(t => t.includes(q))
      ).slice(0, 50);
    }),

  /** Match credentials for a specific technology */
  matchForTech: protectedProcedure
    .input(z.object({
      name: z.string().optional(),
      vendor: z.string().optional(),
      version: z.string().optional(),
      cpe: z.string().optional(),
      port: z.number().optional(),
      protocol: z.string().optional(),
    }))
    .query(({ input }) => {
      return matchCredentialsForTechnology(input);
    }),

  /** Get all credentials (paginated) */
  listAll: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
      protocol: z.string().optional(),
      tag: z.string().optional(),
    }).optional())
    .query(({ input }) => {
      let filtered = [...BUILTIN_DEFAULT_CREDS];
      if (input?.protocol) filtered = filtered.filter(c => c.protocol === input.protocol);
      if (input?.tag) filtered = filtered.filter(c => c.tags.includes(input.tag));
      const total = filtered.length;
      const offset = input?.offset || 0;
      const limit = input?.limit || 50;
      return { credentials: filtered.slice(offset, offset + limit), total };
    }),

  /** Seed built-in credentials to DB */
  seed: protectedProcedure.mutation(async () => {
    const count = await seedBuiltinCredentials();
    return { seeded: count };
  }),

  /** Run credential tests against fingerprinted services */
  runTests: protectedProcedure
    .input(z.object({
      targets: z.array(z.object({
        host: z.string(),
        port: z.number(),
        protocol: z.string(),
        product: z.string().optional(),
        banner: z.string().optional(),
        technologies: z.array(z.object({
          name: z.string().optional(),
          vendor: z.string().optional(),
          version: z.string().optional(),
          cpe: z.string().optional(),
        })).optional(),
      })),
      engagementId: z.number().optional(),
      concurrency: z.number().min(1).max(10).default(3),
      timeoutMs: z.number().min(1000).max(30000).default(8000),
      maxCredsPerTarget: z.number().min(1).max(20).default(10),
    }))
    .mutation(async ({ input, ctx }) => {
      const { runCredentialTests } = await import("../lib/credential-tester");
      const summary = await runCredentialTests(input.targets, {
        concurrency: input.concurrency,
        timeoutMs: input.timeoutMs,
        maxCredsPerTarget: input.maxCredsPerTarget,
        engagementId: input.engagementId,
        operatorId: ctx.user?.id,
      });
      // Convert Map to plain object for serialization
      const byTargetObj: Record<string, any[]> = {};
      summary.byTarget.forEach((v, k) => { byTargetObj[k] = v; });
      return {
        totalTargets: summary.totalTargets,
        totalCredentialsTested: summary.totalCredentialsTested,
        successfulLogins: summary.successfulLogins,
        failedAttempts: summary.failedAttempts,
        timeouts: summary.timeouts,
        errors: summary.errors,
        results: summary.results,
        byTarget: byTargetObj,
      };
    }),

  /** Get matched credentials for a specific host:port (for operator reference) */
  getForService: protectedProcedure
    .input(z.object({
      host: z.string(),
      port: z.number(),
      protocol: z.string(),
      product: z.string().optional(),
      banner: z.string().optional(),
      technologies: z.array(z.object({
        name: z.string().optional(),
        vendor: z.string().optional(),
        version: z.string().optional(),
        cpe: z.string().optional(),
      })).optional(),
    }))
    .query(({ input }) => {
      const { getCredentialsForService } = require("../lib/credential-tester");
      return getCredentialsForService(input);
    }),

  /** Get credentials formatted for ZAP auth playbooks */
  getForZap: protectedProcedure
    .input(z.object({ technologies: z.array(z.string()) }))
    .query(({ input }) => {
      const { getCredentialsForZapPlaybook } = require("../lib/credential-tester");
      return getCredentialsForZapPlaybook(input.technologies);
    }),
});

export const aiChatRouter = router({
  /** Get role-specific chat configuration for the frontend */
  getConfig: protectedProcedure.query(({ ctx }) => {
    const role = ctx.user?.role || 'operator';
    const config = getRoleChatConfig(role);
    return {
      role,
      assistantName: config.assistantName,
      assistantSubtitle: config.assistantSubtitle,
      suggestions: config.suggestions,
      inputPlaceholder: config.inputPlaceholder,
      canViewErrors: config.canViewErrors,
      canViewCreds: config.canViewCreds,
      contextToggles: config.contextToggles,
    };
  }),

  /** Send a message to the role-specialized AI assistant with live platform context */
  send: protectedProcedure
    .input(z.object({
      message: z.string().min(1).max(10000),
      conversationHistory: z.array(z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string(),
      })).max(50).default([]),
      currentPage: z.string().optional(),
      engagementId: z.number().optional(),
      includeErrors: z.boolean().default(false),
      includeCreds: z.boolean().default(false),
      includeRoleContext: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const userRole = ctx.user?.role || 'operator';
      const roleConfig = getRoleChatConfig(userRole);

      // Build the role-specialized system prompt
      const systemParts: string[] = [
        roleConfig.systemPrompt,
        `\nCurrent user: ${ctx.user?.name || 'Unknown'} (role: ${userRole})`,
        `Current page: ${input.currentPage || 'unknown'}`,
      ];

      // Inject live role-specific dashboard context
      if (input.includeRoleContext) {
        try {
          const roleContext = await getRoleContext(userRole);
          if (roleContext) systemParts.push(roleContext);
        } catch { /* ignore context fetch failures */ }
      }

      // Include recent errors if requested and role permits
      if (input.includeErrors && roleConfig.canViewErrors) {
        try {
          const { errors } = await getRecentErrors({ limit: 10, resolved: false });
          if (errors.length > 0) {
            systemParts.push(`\nRecent unresolved platform errors (${errors.length}):`);
            for (const err of errors.slice(0, 5)) {
              systemParts.push(`- [${err.severity}] ${err.source}: ${err.message.slice(0, 200)} (page: ${err.page || 'N/A'})`);
            }
          }
        } catch { /* ignore */ }
      }

      // Include relevant default credentials if requested and role permits
      if (input.includeCreds && roleConfig.canViewCreds) {
        const techKeywords = input.message.match(/\b(cisco|juniper|fortinet|apache|tomcat|mysql|postgres|ssh|ftp|rdp|snmp|mikrotik|ubiquiti|palo alto|sonicwall|vmware|esxi|jenkins|grafana|wordpress|nginx|redis|mongodb|elasticsearch|splunk|siemens|schneider|hikvision|dell|idrac|ilo|supermicro)\b/gi);
        if (techKeywords && techKeywords.length > 0) {
          const uniqueKeywords = [...new Set(techKeywords.map(k => k.toLowerCase()))];
          const allMatches: typeof BUILTIN_DEFAULT_CREDS = [];
          for (const kw of uniqueKeywords) {
            const matches = BUILTIN_DEFAULT_CREDS.filter(c =>
              c.vendor.toLowerCase().includes(kw) || c.product.toLowerCase().includes(kw)
            );
            allMatches.push(...matches);
          }
          if (allMatches.length > 0) {
            systemParts.push(`\nRelevant OEM default credentials for mentioned technologies:`);
            for (const cred of allMatches.slice(0, 15)) {
              systemParts.push(`- ${cred.vendor} ${cred.product}: ${cred.protocol}://${cred.username}:${cred.password}@port:${cred.port || 'default'} (${cred.accessLevel})`);
            }
            systemParts.push(`\nIMPORTANT: Only use these credentials within authorized Rules of Engagement (ROE).`);
          }
        }
      }

      // Include engagement context if provided
      if (input.engagementId) {
        systemParts.push(`\nActive engagement ID: ${input.engagementId}`);
      }

      systemParts.push(`\nRespond concisely. Use markdown formatting. Stay in character as ${roleConfig.assistantName}.`);

      const messages: Array<{ role: "system" | "user" | "assistant"; content: string }> = [
        { role: "system", content: systemParts.join("\n") },
      ];

      // Add conversation history
      for (const msg of input.conversationHistory) {
        messages.push({ role: msg.role, content: msg.content });
      }

      // Add current message
      messages.push({ role: "user", content: input.message });

      try {
        const response = await invokeLLM({ messages });
        const content = response.choices?.[0]?.message?.content || "I apologize, I couldn't generate a response. Please try again.";
        return { reply: content, error: null, role: userRole, assistantName: roleConfig.assistantName };
      } catch (err: any) {
        console.error(`[AiChat:${roleConfig.assistantName}] LLM invocation failed:`, err.message);
        await logPlatformError({
          source: "server",
          severity: "warning",
          message: `AI Chat LLM failure (${roleConfig.assistantName}): ${err.message}`,
          endpoint: "aiChat.send",
          userId: ctx.user?.id,
        });
        return { reply: null, error: "AI service temporarily unavailable. Please try again in a moment.", role: userRole, assistantName: roleConfig.assistantName };
      }
    }),
});
