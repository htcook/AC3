/**
 * Phishing Template & Arsenal Sub-Router
 *
 * Manages GoPhish resources: templates, landing pages, target groups, SMTP profiles.
 * Includes stale resource detection and bulk cleanup.
 * Extracted from phishing-ops.ts for maintainability.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../../_core/trpc";
import { fetchGophish } from "./shared";

export const templateArsenalRouter = router({
  getArsenal: protectedProcedure.query(async () => {
    try {
      const [templates, pages, groups, smtp] = await Promise.all([
        fetchGophish("/api/templates/").catch(() => []),
        fetchGophish("/api/pages/").catch(() => []),
        fetchGophish("/api/groups/").catch(() => []),
        fetchGophish("/api/smtp/").catch(() => []),
      ]);

      return {
        online: true,
        templates: Array.isArray(templates) ? templates : [],
        landingPages: Array.isArray(pages) ? pages : [],
        groups: Array.isArray(groups) ? groups : [],
        sendingProfiles: Array.isArray(smtp) ? smtp : [],
      };
    } catch {
      return { online: false, templates: [], landingPages: [], groups: [], sendingProfiles: [] };
    }
  }),

  deleteGophishTemplate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/templates/${input.id}`, "DELETE");
      return { success: true };
    }),

  deleteGophishPage: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/pages/${input.id}`, "DELETE");
      return { success: true };
    }),

  deleteGophishGroup: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await fetchGophish(`/api/groups/${input.id}`, "DELETE");
      return { success: true };
    }),

  identifyStaleResources: protectedProcedure.query(async () => {
    const [templates, pages, groups] = await Promise.all([
      fetchGophish("/api/templates/").catch(() => []),
      fetchGophish("/api/pages/").catch(() => []),
      fetchGophish("/api/groups/").catch(() => []),
    ]);

    const staleTemplates = (Array.isArray(templates) ? templates : []).filter((t: any) => {
      const html = t.html || '';
      const name = (t.name || '').toLowerCase();
      const isEmpty = html.trim().length < 20;
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(name);
      const noSubject = (t.subject || '').trim().length === 0;
      return isEmpty || isTest || (noSubject && html.trim().length < 100);
    });

    const stalePages = (Array.isArray(pages) ? pages : []).filter((p: any) => {
      const html = p.html || '';
      const name = (p.name || '').toLowerCase();
      const isEmpty = html.trim().length < 20;
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default|^new page/i.test(name);
      return isEmpty || isTest;
    });

    const staleGroups = (Array.isArray(groups) ? groups : []).filter((g: any) => {
      const targets = g.targets || [];
      const name = (g.name || '').toLowerCase();
      const isEmpty = targets.length === 0;
      const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default/i.test(name);
      return isEmpty || isTest;
    });

    return {
      staleTemplates: staleTemplates.map((t: any) => ({
        id: t.id, name: t.name, subject: t.subject || '', htmlLength: (t.html || '').length,
        reason: (t.html || '').trim().length < 20 ? 'empty_body' :
          /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(t.name || '') ? 'test_name' : 'no_subject',
        modifiedDate: t.modified_date,
      })),
      stalePages: stalePages.map((p: any) => ({
        id: p.id, name: p.name, htmlLength: (p.html || '').length,
        reason: (p.html || '').trim().length < 20 ? 'empty_body' : 'test_name',
        modifiedDate: p.modified_date,
      })),
      staleGroups: staleGroups.map((g: any) => ({
        id: g.id, name: g.name, targetCount: (g.targets || []).length,
        reason: (g.targets || []).length === 0 ? 'no_targets' : 'test_name',
        modifiedDate: g.modified_date,
      })),
      summary: {
        totalStale: staleTemplates.length + stalePages.length + staleGroups.length,
        staleTemplateCount: staleTemplates.length,
        stalePageCount: stalePages.length,
        staleGroupCount: staleGroups.length,
      },
    };
  }),

  bulkCleanup: protectedProcedure
    .input(z.object({
      templateIds: z.array(z.number()).default([]),
      pageIds: z.array(z.number()).default([]),
      groupIds: z.array(z.number()).default([]),
    }))
    .mutation(async ({ input }) => {
      const results = { deletedTemplates: 0, deletedPages: 0, deletedGroups: 0, errors: [] as string[] };

      for (const id of input.templateIds) {
        try { await fetchGophish(`/api/templates/${id}`, "DELETE"); results.deletedTemplates++; }
        catch (e: any) { results.errors.push(`Template ${id}: ${e.message}`); }
      }
      for (const id of input.pageIds) {
        try { await fetchGophish(`/api/pages/${id}`, "DELETE"); results.deletedPages++; }
        catch (e: any) { results.errors.push(`Page ${id}: ${e.message}`); }
      }
      for (const id of input.groupIds) {
        try { await fetchGophish(`/api/groups/${id}`, "DELETE"); results.deletedGroups++; }
        catch (e: any) { results.errors.push(`Group ${id}: ${e.message}`); }
      }

      return results;
    }),
});
