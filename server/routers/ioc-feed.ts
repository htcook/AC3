import { TRPCError } from "@trpc/server";
import { protectedProcedure, publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { sum } from "drizzle-orm";

export const iocFeedRouter = router({
    // Fetch from CISA KEV
    fetchCisaKev: protectedProcedure.mutation(async () => {
      try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (!response.ok) throw new Error(`CISA KEV fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const vulnerabilities = data.vulnerabilities || [];

        const entries: InsertIocFeed[] = vulnerabilities.slice(0, 500).map((vuln: any) => ({
          feedSource: 'cisa_kev',
          feedType: 'vulnerability',
          title: vuln.vulnerabilityName || vuln.cveID,
          description: vuln.shortDescription,
          severity: 'critical' as const,
          iocType: 'cve',
          iocValue: vuln.cveID,
          cveId: vuln.cveID,
          vendorProduct: vuln.vendorProject ? `${vuln.vendorProject} ${vuln.product}` : vuln.product,
          knownRansomware: vuln.knownRansomwareCampaignUse === 'Known',
          dateAdded: vuln.dateAdded,
          dueDate: vuln.dueDate,
          linkedActors: [],
          tags: [vuln.vendorProject, vuln.product].filter(Boolean),
          rawData: vuln,
        }));

        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }

        return { source: 'cisa_kev', fetched: entries.length, total: vulnerabilities.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `CISA KEV fetch error: ${err.message}` });
      }
    }),

    // Fetch from abuse.ch URLhaus
    fetchAbuseCh: protectedProcedure.mutation(async () => {
      try {
        const apiKey = process.env.ABUSECH_API_KEY || '';
        const headers: Record<string, string> = {};
        if (apiKey) headers['Auth-Key'] = apiKey;
        const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/', {
          method: 'GET',
          headers,
        });
        if (!response.ok) throw new Error(`abuse.ch fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const urls = data.urls || [];

        const entries: InsertIocFeed[] = urls.map((url: any) => ({
          feedSource: 'abusech_urlhaus',
          feedType: 'url',
          title: url.threat || 'Malicious URL',
          description: `URL: ${url.url} | Threat: ${url.threat} | Status: ${url.url_status}`,
          severity: url.threat === 'malware_download' ? 'high' as const : 'medium' as const,
          iocType: 'url',
          iocValue: url.url,
          dateAdded: url.date_added,
          linkedActors: [],
          tags: url.tags || [],
          rawData: url,
        }));

        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }

        return { source: 'abusech_urlhaus', fetched: entries.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `abuse.ch fetch error: ${err.message}` });
      }
    }),

    // Fetch from abuse.ch ThreatFox
    fetchThreatFox: protectedProcedure.mutation(async () => {
      try {
        const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'get_iocs', days: 7 }),
        });
        if (!response.ok) throw new Error(`ThreatFox fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const iocs = data.data || [];

        const entries: InsertIocFeed[] = (Array.isArray(iocs) ? iocs : []).slice(0, 200).map((ioc: any) => ({
          feedSource: 'abusech_threatfox',
          feedType: ioc.ioc_type || 'unknown',
          title: ioc.malware_printable || ioc.threat_type || 'IOC',
          description: `${ioc.ioc_type}: ${ioc.ioc} | Malware: ${ioc.malware_printable} | Confidence: ${ioc.confidence_level}%`,
          severity: (ioc.confidence_level || 0) > 75 ? 'high' as const : 'medium' as const,
          iocType: ioc.ioc_type?.includes('hash') ? 'hash' : ioc.ioc_type?.includes('domain') ? 'domain' : ioc.ioc_type?.includes('ip') ? 'ip' : 'url',
          iocValue: ioc.ioc,
          dateAdded: ioc.first_seen_utc,
          linkedActors: ioc.malware_alias ? [ioc.malware_alias] : [],
          tags: ioc.tags || [],
          rawData: ioc,
        }));

        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }

        return { source: 'abusech_threatfox', fetched: entries.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `ThreatFox fetch error: ${err.message}` });
      }
    }),

    // List IOC feed entries
    list: publicProcedure
      .input(z.object({
        feedSource: z.string().optional(),
        severity: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listIocFeedEntries(input || {});
      }),

    stats: publicProcedure.query(async () => {
      return db.getIocFeedStats();
    }),

    // Fetch all feeds at once
    fetchAll: protectedProcedure.mutation(async () => {
      const results: { source: string; fetched: number; error?: string }[] = [];

      // CISA KEV
      try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (response.ok) {
          const data = await response.json() as any;
          const vulns = (data.vulnerabilities || []).slice(0, 300);
          const entries: InsertIocFeed[] = vulns.map((v: any) => ({
            feedSource: 'cisa_kev', feedType: 'vulnerability',
            title: v.vulnerabilityName || v.cveID, description: v.shortDescription,
            severity: 'critical' as const, iocType: 'cve', iocValue: v.cveID,
            cveId: v.cveID, vendorProduct: `${v.vendorProject || ''} ${v.product || ''}`.trim(),
            knownRansomware: v.knownRansomwareCampaignUse === 'Known',
            dateAdded: v.dateAdded, dueDate: v.dueDate,
            linkedActors: [], tags: [v.vendorProject, v.product].filter(Boolean), rawData: v,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'cisa_kev', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'cisa_kev', fetched: 0, error: err.message }); }

      // abuse.ch URLhaus
      try {
        const urlhausHeaders: Record<string, string> = {};
        const urlhausKey = process.env.ABUSECH_API_KEY || '';
        if (urlhausKey) urlhausHeaders['Auth-Key'] = urlhausKey;
        const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/', {
          method: 'GET', headers: urlhausHeaders,
        });
        if (response.ok) {
          const data = await response.json() as any;
          const urls = data.urls || [];
          const entries: InsertIocFeed[] = urls.map((u: any) => ({
            feedSource: 'abusech_urlhaus', feedType: 'url',
            title: u.threat || 'Malicious URL', description: `URL: ${u.url} | Threat: ${u.threat}`,
            severity: u.threat === 'malware_download' ? 'high' as const : 'medium' as const,
            iocType: 'url', iocValue: u.url, dateAdded: u.date_added,
            linkedActors: [], tags: u.tags || [], rawData: u,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'abusech_urlhaus', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'abusech_urlhaus', fetched: 0, error: err.message }); }

      // abuse.ch ThreatFox
      try {
        const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'get_iocs', days: 7 }),
        });
        if (response.ok) {
          const data = await response.json() as any;
          const iocs = Array.isArray(data.data) ? data.data.slice(0, 200) : [];
          const entries: InsertIocFeed[] = iocs.map((i: any) => ({
            feedSource: 'abusech_threatfox', feedType: i.ioc_type || 'unknown',
            title: i.malware_printable || 'IOC',
            description: `${i.ioc_type}: ${i.ioc} | Malware: ${i.malware_printable}`,
            severity: (i.confidence_level || 0) > 75 ? 'high' as const : 'medium' as const,
            iocType: i.ioc_type?.includes('hash') ? 'hash' : i.ioc_type?.includes('domain') ? 'domain' : 'url',
            iocValue: i.ioc, dateAdded: i.first_seen_utc,
            linkedActors: [], tags: i.tags || [], rawData: i,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'abusech_threatfox', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'abusech_threatfox', fetched: 0, error: err.message }); }

      return { results, totalFetched: results.reduce((sum, r) => sum + r.fetched, 0) };
    }),

    // Manual trigger for IOC sync (uses the centralized sync service)
    triggerSync: protectedProcedure.mutation(async () => {
      const { runIocSync, isSyncRunning } = await import("../lib/ioc-sync");
      if (isSyncRunning()) {
        throw new TRPCError({ code: 'CONFLICT', message: 'IOC sync is already running' });
      }
      const result = await runIocSync('manual');
      return result;
    }),

    // Get sync history
    syncHistory: publicProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        return db.listIocSyncLogs(input?.limit || 20);
      }),

    // Get last successful sync
    lastSync: publicProcedure.query(async () => {
      return db.getLastIocSync();
    }),

    // Check if sync is running
    syncStatus: publicProcedure.query(async () => {
      const { isSyncRunning } = await import("../lib/ioc-sync");
      return { running: isSyncRunning() };
    }),
  });
