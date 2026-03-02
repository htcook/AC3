import * as db from "../db";
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
import { buildKnowledgeContextForLLM, searchTechniques, searchTools } from "../lib/pentest-knowledge-base";
import { KnowledgeIndex, getRagSources, buildAttributionNotice, autoTagDocument } from "../lib/knowledge-store";
import { getRoleActions, actionsToLLMTools } from "../lib/role-quick-actions";
import { executeQuickAction } from "../lib/quick-action-executor";
import { chatSessions, chatMessages } from "../../drizzle/schema";
import { getDb } from "../db";
import { eq, desc, and, count as drizzleCount } from "drizzle-orm";

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
  // ─── Chat Configuration ─────────────────────────────────────────────

  /** Get role-specific chat configuration for the frontend */
  getConfig: protectedProcedure
    .input(z.object({ personaOverride: z.string().optional() }).optional())
    .query(({ ctx, input }) => {
      const isAdmin = ctx.user?.role === 'admin';
      const effectiveRole = (isAdmin && input?.personaOverride) ? input.personaOverride : (ctx.user?.role || 'operator');
      const config = getRoleChatConfig(effectiveRole);
      const actions = getRoleActions(effectiveRole);
      return {
        role: effectiveRole,
        isPersonaOverride: isAdmin && !!input?.personaOverride && input.personaOverride !== ctx.user?.role,
        assistantName: config.assistantName,
        assistantSubtitle: config.assistantSubtitle,
        suggestions: config.suggestions,
        inputPlaceholder: config.inputPlaceholder,
        canViewErrors: config.canViewErrors,
        canViewCreds: config.canViewCreds,
        contextToggles: config.contextToggles,
        quickActions: actions.map(a => ({ name: a.name, displayName: a.displayName, description: a.description, icon: a.icon, confirmRequired: a.confirmRequired })),
        canSwitchPersona: isAdmin,
        availablePersonas: isAdmin ? ['operator', 'executive', 'analyst', 'team_lead', 'client', 'admin'] : [],
      };
    }),

  // ─── Chat Session Persistence ───────────────────────────────────────

  /** List chat sessions for the current user */
  listSessions: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(20), includeArchived: z.boolean().default(false) }).optional())
    .query(async ({ ctx, input }) => {
      const db = (await getDb())!;
      const userId = ctx.user!.id;
      const limit = input?.limit || 20;
      const conditions = input?.includeArchived
        ? eq(chatSessions.userId, userId)
        : and(eq(chatSessions.userId, userId), eq(chatSessions.archived, false));
      const sessions = await db.select().from(chatSessions)
        .where(conditions!)
        .orderBy(desc(chatSessions.lastMessageAt))
        .limit(limit);
      return sessions;
    }),

  /** Create a new chat session */
  createSession: protectedProcedure
    .input(z.object({ title: z.string().max(255).optional(), role: z.string().optional() }))
    .mutation(async ({ ctx, input }) => {
      const db = (await getDb())!;
      const userId = ctx.user!.id;
      const role = input.role || ctx.user?.role || 'operator';
      const [result] = await db.insert(chatSessions).values({
        userId,
        title: input.title || 'New Chat',
        role,
        messageCount: 0,
      });
      const sessionId = result.insertId;
      const [session] = await db.select().from(chatSessions).where(eq(chatSessions.id, Number(sessionId)));
      return session;
    }),

  /** Load messages for a chat session */
  loadMessages: protectedProcedure
    .input(z.object({ sessionId: z.number(), limit: z.number().min(1).max(200).default(100) }))
    .query(async ({ ctx, input }) => {
      const db = (await getDb())!;
      // Verify ownership
      const [session] = await db.select().from(chatSessions)
        .where(and(eq(chatSessions.id, input.sessionId), eq(chatSessions.userId, ctx.user!.id)));
      if (!session) throw new Error('Session not found');
      const msgs = await db.select().from(chatMessages)
        .where(eq(chatMessages.sessionId, input.sessionId))
        .orderBy(chatMessages.createdAt)
        .limit(input.limit);
      return { session, messages: msgs };
    }),

  /** Archive a chat session */
  archiveSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      const db = (await getDb())!;
      await db.update(chatSessions)
        .set({ archived: true })
        .where(and(eq(chatSessions.id, input.sessionId), eq(chatSessions.userId, ctx.user!.id)));
      return { success: true };
    }),

  /** Delete a chat session and its messages */
  deleteSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      const db = (await getDb())!;
      // Verify ownership
      const [session] = await db.select().from(chatSessions)
        .where(and(eq(chatSessions.id, input.sessionId), eq(chatSessions.userId, ctx.user!.id)));
      if (!session) throw new Error('Session not found');
      await db.delete(chatMessages).where(eq(chatMessages.sessionId, input.sessionId));
      await db.delete(chatSessions).where(eq(chatSessions.id, input.sessionId));
      return { success: true };
    }),

  /** Rename a chat session */
  renameSession: protectedProcedure
    .input(z.object({ sessionId: z.number(), title: z.string().min(1).max(255) }))
    .mutation(async ({ ctx, input }) => {
      const db = (await getDb())!;
      await db.update(chatSessions)
        .set({ title: input.title })
        .where(and(eq(chatSessions.id, input.sessionId), eq(chatSessions.userId, ctx.user!.id)));
      return { success: true };
    }),

  // ─── Enhanced Send with Tool-Calling & Persistence ──────────────────

  /** Send a message to the role-specialized AI assistant with tool-calling and persistence */
  send: protectedProcedure
    .input(z.object({
      message: z.string().min(1).max(10000),
      sessionId: z.number().optional(),
      conversationHistory: z.array(z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string(),
      })).max(50).default([]),
      currentPage: z.string().optional(),
      engagementId: z.number().optional(),
      includeErrors: z.boolean().default(false),
      includeCreds: z.boolean().default(false),
      includeRoleContext: z.boolean().default(true),
      includeKnowledgeBase: z.boolean().default(true),
      enableToolCalling: z.boolean().default(true),
      personaOverride: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const isAdmin = ctx.user?.role === 'admin';
      const userRole = (isAdmin && input.personaOverride) ? input.personaOverride : (ctx.user?.role || 'operator');
      const roleConfig = getRoleChatConfig(userRole);
      const db = (await getDb())!;

      // ── Persist user message if session provided ──
      let sessionId = input.sessionId;
      if (sessionId) {
        await db.insert(chatMessages).values({ sessionId, role: 'user', content: input.message });
        await db.update(chatSessions).set({ messageCount: (await db.select({ cnt: drizzleCount() }).from(chatMessages).where(eq(chatMessages.sessionId, sessionId)))[0]?.cnt || 0, lastMessageAt: new Date() }).where(eq(chatSessions.id, sessionId));
      }

      // ── Build the role-specialized system prompt ──
      const systemParts: string[] = [
        roleConfig.systemPrompt,
        `\nCurrent user: ${ctx.user?.name || 'Unknown'} (role: ${userRole})`,
        `Current page: ${input.currentPage || 'unknown'}`,
      ];

      if (input.includeRoleContext) {
        try {
          const roleContext = await getRoleContext(userRole);
          if (roleContext) systemParts.push(roleContext);
        } catch { /* ignore */ }
      }

      // ── Inject pentest knowledge base context ──
      if (input.includeKnowledgeBase) {
        try {
          const knowledgeContext = buildKnowledgeContextForLLM(userRole as any, 3000);
          if (knowledgeContext) {
            systemParts.push(`\n--- PENTEST KNOWLEDGE BASE ---`);
            systemParts.push(knowledgeContext);
          }

          // Dynamic technique lookup based on user message keywords
          const techKeywords = input.message.match(/\b(nmap|burp|metasploit|sqlmap|bloodhound|mimikatz|kerberos|privesc|lateral|persistence|exfiltration|buffer overflow|rop|seh|shellcode|xss|sqli|ssrf|ssti|xxe|lfi|rfi|deserialization|command injection|path traversal|upload bypass|password spray|hash crack|responder|ntlm|smb|ldap|snmp|dns|ad enum|active directory|cobalt strike|sliver|havoc|c2|beacon|implant)\b/gi);
          if (techKeywords && techKeywords.length > 0) {
            const uniqueKw = [...new Set(techKeywords.map(k => k.toLowerCase()))];
            const matchedTechniques: string[] = [];
            const matchedTools: string[] = [];
            for (const kw of uniqueKw.slice(0, 5)) {
              const techs = searchTechniques(kw);
              for (const t of techs.slice(0, 2)) {
                matchedTechniques.push(`  - ${t.name} [${t.mitreTechniqueId}]: ${t.description.substring(0, 150)}`);
                if (t.commonPayloads.length > 0) matchedTechniques.push(`    Payloads: ${t.commonPayloads.slice(0, 3).join(' | ')}`);
                if (t.defenseBypass.length > 0) matchedTechniques.push(`    Evasion: ${t.defenseBypass.slice(0, 2).join(' | ')}`);
              }
              const tools = searchTools(kw);
              for (const tl of tools.slice(0, 1)) {
                matchedTools.push(`  - ${tl.displayName}: ${tl.quickReference.slice(0, 3).join(' | ')}`);
              }
            }
            if (matchedTechniques.length > 0) {
              systemParts.push(`\n--- RELEVANT TECHNIQUES (matched from query) ---`);
              systemParts.push(matchedTechniques.join('\n'));
            }
            if (matchedTools.length > 0) {
              systemParts.push(`\n--- RELEVANT TOOL REFERENCES ---`);
              systemParts.push(matchedTools.join('\n'));
            }
          }
        } catch { /* ignore knowledge base errors */ }
      }

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

      if (input.engagementId) {
        systemParts.push(`\nActive engagement ID: ${input.engagementId}`);
      }

      systemParts.push(`\nRespond concisely. Use markdown formatting. Stay in character as ${roleConfig.assistantName}.`);
      systemParts.push(`When you use a tool/function, briefly explain what you're doing and present the results clearly.`);

      const messages: Array<{ role: "system" | "user" | "assistant" | "tool"; content: string; tool_call_id?: string }> = [
        { role: "system", content: systemParts.join("\n") },
      ];

      for (const msg of input.conversationHistory) {
        messages.push({ role: msg.role, content: msg.content });
      }
      messages.push({ role: "user", content: input.message });

      // ── Prepare tool-calling ──
      const roleActions = getRoleActions(userRole);
      const tools = input.enableToolCalling && roleActions.length > 0 ? actionsToLLMTools(roleActions) : undefined;

      try {
        // First LLM call — may return a tool call or a direct response
        const response = await invokeLLM({ messages, tools, tool_choice: tools ? 'auto' : undefined } as any);
        const choice = response.choices?.[0];
        const toolCalls = choice?.message?.tool_calls;
        let executedActions: Array<{ name: string; displayName: string; result: any; confirmRequired: boolean }> = [];

        // ── Handle tool calls ──
        if (toolCalls && toolCalls.length > 0) {
          // Execute each tool call
          for (const tc of toolCalls) {
            const fnName = tc.function?.name;
            let fnArgs: Record<string, any> = {};
            try { fnArgs = JSON.parse(tc.function?.arguments || '{}'); } catch { /* ignore */ }

            const actionDef = roleActions.find(a => a.name === fnName);
            const result = await executeQuickAction(fnName, fnArgs);
            executedActions.push({
              name: fnName,
              displayName: actionDef?.displayName || fnName,
              result,
              confirmRequired: actionDef?.confirmRequired || false,
            });

            // Persist tool message if session exists
            if (sessionId) {
              await db.insert(chatMessages).values({
                sessionId,
                role: 'tool',
                content: result.message,
                toolName: fnName,
                toolResult: result,
              });
            }

            // Feed tool result back to LLM
            messages.push({ role: "assistant" as any, content: "", ...({ tool_calls: [tc] } as any) });
            messages.push({ role: "tool", content: JSON.stringify(result), tool_call_id: tc.id });
          }

          // Second LLM call — with tool results
          const followUp = await invokeLLM({ messages } as any);
          const content = followUp.choices?.[0]?.message?.content || "Action completed. See the results above.";

          // Persist assistant response
          if (sessionId) {
            await db.insert(chatMessages).values({ sessionId, role: 'assistant', content });
            await db.update(chatSessions).set({ messageCount: (await db.select({ cnt: drizzleCount() }).from(chatMessages).where(eq(chatMessages.sessionId, sessionId)))[0]?.cnt || 0, lastMessageAt: new Date() }).where(eq(chatSessions.id, sessionId));
          }

          // Auto-generate title from first user message
          if (sessionId && input.conversationHistory.length === 0) {
            const shortTitle = input.message.slice(0, 60) + (input.message.length > 60 ? '...' : '');
            await db.update(chatSessions).set({ title: shortTitle }).where(eq(chatSessions.id, sessionId));
          }

          return {
            reply: content,
            error: null,
            role: userRole,
            assistantName: roleConfig.assistantName,
            executedActions,
            sessionId,
          };
        }

        // ── Direct response (no tool calls) ──
        const content = choice?.message?.content || "I apologize, I couldn't generate a response. Please try again.";

        // Persist assistant response
        if (sessionId) {
          await db.insert(chatMessages).values({ sessionId, role: 'assistant', content });
          await db.update(chatSessions).set({ messageCount: (await db.select({ cnt: drizzleCount() }).from(chatMessages).where(eq(chatMessages.sessionId, sessionId)))[0]?.cnt || 0, lastMessageAt: new Date() }).where(eq(chatSessions.id, sessionId));
        }

        // Auto-generate title from first user message
        if (sessionId && input.conversationHistory.length === 0) {
          const shortTitle = input.message.slice(0, 60) + (input.message.length > 60 ? '...' : '');
          await db.update(chatSessions).set({ title: shortTitle }).where(eq(chatSessions.id, sessionId));
        }

        return { reply: content, error: null, role: userRole, assistantName: roleConfig.assistantName, executedActions: [], sessionId };
      } catch (err: any) {
        console.error(`[AiChat:${roleConfig.assistantName}] LLM invocation failed:`, err.message);
        await logPlatformError({
          source: "server",
          severity: "warning",
          message: `AI Chat LLM failure (${roleConfig.assistantName}): ${err.message}`,
          endpoint: "aiChat.send",
          userId: ctx.user?.id,
        });
        return { reply: null, error: "AI service temporarily unavailable. Please try again in a moment.", role: userRole, assistantName: roleConfig.assistantName, executedActions: [], sessionId };
      }
    }),
});
