/**
 * Live Infrastructure tRPC Router
 * Endpoints for AWS EC2 instances, DNS automation, and scheduled scans.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import * as doInfra from "../lib/aws-ec2-infra";
import * as dns from "../lib/dns-automation";
import * as scans from "../lib/opsec-scheduled-scans";

export const liveInfraRouter = router({
  // ─── Droplets ─────────────────────────────────────────────────────────────
  droplets: router({
    list: protectedProcedure
      .input(z.object({ tag: z.string().optional() }).optional())
      .query(async ({ input }) => doInfra.listDroplets(input?.tag)),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => doInfra.getDroplet(input.id)),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        region: z.string().default("sfo3"),
        size: z.string().default("s-1vcpu-1gb"),
        image: z.string().default("ubuntu-22-04-x64"),
        sshKeys: z.array(z.number()).optional(),
        tags: z.array(z.string()).optional(),
        userData: z.string().optional(),
      }))
      .mutation(async ({ input }) => doInfra.createDroplet(input)),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => { await doInfra.deleteDroplet(input.id); return { success: true }; }),

    healthCheck: protectedProcedure
      .input(z.object({ tag: z.string().optional() }).optional())
      .query(async ({ input }) => doInfra.healthCheckAll(input?.tag)),
  }),

  // ─── Firewalls ────────────────────────────────────────────────────────────
  firewalls: router({
    list: protectedProcedure.query(async () => doInfra.listFirewalls()),
    delete: protectedProcedure
      .input(z.object({ id: z.string() }))
      .mutation(async ({ input }) => { await doInfra.deleteFirewall(input.id); return { success: true }; }),
  }),

  // ─── SSH Keys ─────────────────────────────────────────────────────────────
  sshKeys: router({
    list: protectedProcedure.query(async () => doInfra.listSshKeys()),
  }),

  // ─── User Data Generators ─────────────────────────────────────────────────
  userData: router({
    redirector: protectedProcedure
      .input(z.object({
        type: z.enum(["http", "smtp", "dns", "c2"]),
        backendHost: z.string(),
        backendPort: z.number(),
        adminCidr: z.string().optional(),
      }))
      .query(({ input }) => ({ script: doInfra.generateRedirectorUserData(input) })),

    teamServer: protectedProcedure
      .input(z.object({ calderaPort: z.number().optional(), adminCidr: z.string().optional() }).optional())
      .query(({ input }) => ({ script: doInfra.generateTeamServerUserData(input ?? {}) })),
  }),

  // ─── DNS Automation ───────────────────────────────────────────────────────
  dns: router({
    domains: protectedProcedure.query(async () => dns.listDomains()),

    records: protectedProcedure
      .input(z.object({ domain: z.string() }))
      .query(async ({ input }) => dns.listRecords(input.domain)),

    createRecord: protectedProcedure
      .input(z.object({
        domain: z.string(),
        type: z.string(),
        name: z.string(),
        data: z.string(),
        ttl: z.number().optional(),
        priority: z.number().optional(),
      }))
      .mutation(async ({ input }) => dns.createRecord(input.domain, input)),

    deleteRecord: protectedProcedure
      .input(z.object({ domain: z.string(), recordId: z.number() }))
      .mutation(async ({ input }) => { await dns.deleteRecord(input.domain, input.recordId); return { success: true }; }),

    deployEmail: protectedProcedure
      .input(z.object({
        domain: z.string(),
        spfIncludes: z.array(z.string()).optional(),
        spfIps: z.array(z.string()).optional(),
        spfPolicy: z.enum(["~all", "-all", "?all"]).optional(),
        dmarcPolicy: z.enum(["none", "quarantine", "reject"]).optional(),
        dmarcRua: z.string().optional(),
        dkimSelector: z.string().optional(),
        mxHost: z.string().optional(),
        mxPriority: z.number().optional(),
      }))
      .mutation(async ({ input }) => dns.deployEmailRecords(input.domain, input)),

    validate: protectedProcedure
      .input(z.object({ domain: z.string(), dkimSelector: z.string().optional() }))
      .query(async ({ input }) => dns.validateEmailDns(input.domain, input.dkimSelector)),

    generateSpf: protectedProcedure
      .input(z.object({ includes: z.array(z.string()).optional(), ips: z.array(z.string()).optional(), policy: z.enum(["~all", "-all", "?all"]).optional() }))
      .query(({ input }) => ({ record: dns.generateSpfRecord(input) })),

    generateDmarc: protectedProcedure
      .input(z.object({ policy: z.enum(["none", "quarantine", "reject"]).optional(), rua: z.string().optional(), ruf: z.string().optional(), pct: z.number().optional() }))
      .query(({ input }) => ({ record: dns.generateDmarcRecord(input) })),
  }),

  // ─── Scheduled Scans ──────────────────────────────────────────────────────
  scans: router({
    checks: protectedProcedure.query(() => scans.getBuiltinChecks()),

    checksByCategory: protectedProcedure
      .input(z.object({ category: z.string() }))
      .query(({ input }) => scans.getChecksByCategory(input.category)),

    execute: protectedProcedure
      .input(z.object({
        target: z.object({ id: z.string(), name: z.string(), host: z.string(), port: z.number().default(22), tags: z.array(z.string()).default([]) }),
        checkIds: z.array(z.string()).optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ── ROE Scope Enforcement: validate target host ──
        if (input.engagementId) {
          const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceTargetScope(input.engagementId, input.target.host, "Live Infra Scan", ctx);
        }
        return scans.executeScan(input.target, input.checkIds);
      }),

    scheduled: router({
      list: protectedProcedure.query(() => scans.listScheduledScans()),

      create: protectedProcedure
        .input(z.object({
          name: z.string(),
          targets: z.array(z.object({ id: z.string(), name: z.string(), host: z.string(), port: z.number().default(22), tags: z.array(z.string()).default([]) })),
          checks: z.array(z.string()).optional(),
          intervalHours: z.number().min(1),
          notifyOnFail: z.boolean().optional(),
          notifyThreshold: z.number().min(0).max(100).optional(),
        }))
        .mutation(({ input }) => scans.createScheduledScan(input)),

      delete: protectedProcedure
        .input(z.object({ id: z.string() }))
        .mutation(({ input }) => ({ success: scans.deleteScheduledScan(input.id) })),

      toggle: protectedProcedure
        .input(z.object({ id: z.string(), enabled: z.boolean() }))
        .mutation(({ input }) => scans.toggleScheduledScan(input.id, input.enabled)),

      run: protectedProcedure
        .input(z.object({ id: z.string() }))
        .mutation(async ({ input }) => scans.runScheduledScan(input.id)),
    }),

    history: protectedProcedure
      .input(z.object({ targetId: z.string() }))
      .query(({ input }) => scans.getScanHistory(input.targetId)),

    allHistory: protectedProcedure.query(() => scans.getAllScanHistory()),
  }),
});
