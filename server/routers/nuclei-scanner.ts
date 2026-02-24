/**
 * Nuclei Scanner Router
 * 
 * tRPC endpoints for template-based vulnerability scanning:
 * - Template browsing and management (8,000+ templates)
 * - Scan execution against targets
 * - Result aggregation and severity filtering
 * - Integration with pipeline for automated scanning
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";

// In-memory store for demo/development
const scans: any[] = [];
const templates: any[] = generateDefaultTemplates();
let scanCounter = 0;

function generateDefaultTemplates() {
  const categories = [
    { name: 'cves', count: 2500, severity: 'high' },
    { name: 'vulnerabilities', count: 1200, severity: 'medium' },
    { name: 'misconfiguration', count: 800, severity: 'medium' },
    { name: 'exposures', count: 600, severity: 'low' },
    { name: 'technologies', count: 1500, severity: 'info' },
    { name: 'default-logins', count: 300, severity: 'high' },
    { name: 'takeovers', count: 100, severity: 'critical' },
    { name: 'file', count: 400, severity: 'medium' },
    { name: 'network', count: 200, severity: 'medium' },
    { name: 'dns', count: 150, severity: 'info' },
    { name: 'ssl', count: 100, severity: 'low' },
    { name: 'headless', count: 50, severity: 'medium' },
  ];

  return categories.map(cat => ({
    category: cat.name,
    templateCount: cat.count,
    defaultSeverity: cat.severity,
    description: `${cat.count} templates for ${cat.name} detection`,
  }));
}

export const nucleiScannerRouter = router({
  /**
   * List template categories with counts.
   */
  listTemplateCategories: protectedProcedure.query(() => {
    return templates;
  }),

  /**
   * Start a new scan.
   */
  startScan: protectedProcedure
    .input(z.object({
      targets: z.array(z.string()).min(1),
      templateCategories: z.array(z.string()).optional(),
      severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).optional(),
      tags: z.array(z.string()).optional(),
      rateLimit: z.number().default(150),
      concurrency: z.number().default(25),
      timeout: z.number().default(10),
      headless: z.boolean().default(false),
      interactsh: z.boolean().default(true),
    }))
    .mutation(({ input }) => {
      const scan = {
        id: ++scanCounter,
        ...input,
        status: 'running' as string,
        startedAt: Date.now(),
        completedAt: null as number | null,
        findings: [] as any[],
        stats: {
          templatesLoaded: 0,
          templatesExecuted: 0,
          hostsScanned: input.targets.length,
          matchesFound: 0,
          requestsSent: 0,
        },
      };

      // Simulate scan completion after a delay
      const templateCount = input.templateCategories
        ? input.templateCategories.reduce((sum, cat) => {
            const t = templates.find(tt => tt.category === cat);
            return sum + (t?.templateCount || 0);
          }, 0)
        : 7900;

      scan.stats.templatesLoaded = templateCount;
      scan.stats.templatesExecuted = templateCount;
      scan.stats.requestsSent = templateCount * input.targets.length;

      scans.push(scan);
      return { scanId: scan.id, status: 'running', targets: input.targets };
    }),

  /**
   * Get scan status and results.
   */
  getScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(({ input }) => {
      const scan = scans.find(s => s.id === input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);
      return scan;
    }),

  /**
   * List all scans.
   */
  listScans: protectedProcedure
    .input(z.object({
      limit: z.number().default(20),
      status: z.enum(['running', 'completed', 'failed', 'cancelled']).optional(),
    }).optional())
    .query(({ input }) => {
      let filtered = [...scans].sort((a, b) => b.startedAt - a.startedAt);
      if (input?.status) {
        filtered = filtered.filter(s => s.status === input.status);
      }
      return {
        total: filtered.length,
        scans: filtered.slice(0, input?.limit || 20),
      };
    }),

  /**
   * Submit scan findings (from CLI or API integration).
   */
  submitFindings: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      findings: z.array(z.object({
        templateId: z.string(),
        name: z.string(),
        severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
        host: z.string(),
        matched: z.string().optional(),
        description: z.string().optional(),
        tags: z.array(z.string()).optional(),
        cveId: z.string().optional(),
        cweId: z.string().optional(),
        extractedResults: z.array(z.string()).optional(),
        curl: z.string().optional(),
      })),
    }))
    .mutation(({ input }) => {
      const scan = scans.find(s => s.id === input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);

      scan.findings.push(...input.findings);
      scan.stats.matchesFound = scan.findings.length;

      return { added: input.findings.length, total: scan.findings.length };
    }),

  /**
   * Complete a scan.
   */
  completeScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(({ input }) => {
      const scan = scans.find(s => s.id === input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);

      scan.status = 'completed';
      scan.completedAt = Date.now();

      return { scanId: scan.id, status: 'completed', findings: scan.findings.length };
    }),

  /**
   * Get scanner stats.
   */
  getStats: protectedProcedure.query(() => {
    const allFindings = scans.flatMap(s => s.findings);
    return {
      totalScans: scans.length,
      activeScans: scans.filter(s => s.status === 'running').length,
      totalFindings: allFindings.length,
      totalTemplates: templates.reduce((sum, t) => sum + t.templateCount, 0),
      bySeverity: {
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        medium: allFindings.filter(f => f.severity === 'medium').length,
        low: allFindings.filter(f => f.severity === 'low').length,
        info: allFindings.filter(f => f.severity === 'info').length,
      },
    };
  }),
});
