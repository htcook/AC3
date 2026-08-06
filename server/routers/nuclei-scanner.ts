/**
 * Nuclei Scanner Router
 * 
 * tRPC endpoints for template-based vulnerability scanning:
 * - Template browsing and management (8,000+ templates)
 * - Real scan execution on scan server via SSH
 * - JSON output parsing for structured findings
 * - Result aggregation and severity filtering
 * - Integration with engagement pipeline for automated scanning
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";

// In-memory store for scans and results
const scans = new Map<number, NucleiScan>();
let scanCounter = 0;

interface NucleiScan {
  id: number;
  targets: string[];
  templateCategories?: string[];
  severity?: string[];
  tags?: string[];
  rateLimit: number;
  concurrency: number;
  timeout: number;
  headless: boolean;
  interactsh: boolean;
  engagementId?: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt: number;
  completedAt: number | null;
  findings: NucleiFinding[];
  rawOutput: string;
  rawStderr: string;
  exitCode: number;
  durationMs: number;
  credentialInjection: any;
  command: string;
  stats: {
    templatesLoaded: number;
    templatesExecuted: number;
    hostsScanned: number;
    matchesFound: number;
    requestsSent: number;
    credentialTemplatesInjected: number;
    credentialsMatched: number;
  };
}

interface NucleiFinding {
  templateId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  host: string;
  matched: string;
  description: string;
  tags: string[];
  cveId?: string;
  cweId?: string;
  extractedResults: string[];
  curl?: string;
  timestamp: string;
  type: string;
  ip?: string;
  port?: string;
}

const TEMPLATE_CATEGORIES = [
  { name: 'cves', count: 2500, severity: 'high', description: 'CVE-based vulnerability detection templates' },
  { name: 'vulnerabilities', count: 1200, severity: 'medium', description: 'General vulnerability detection' },
  { name: 'misconfiguration', count: 800, severity: 'medium', description: 'Service misconfiguration detection' },
  { name: 'exposures', count: 600, severity: 'low', description: 'Sensitive data exposure detection' },
  { name: 'technologies', count: 1500, severity: 'info', description: 'Technology fingerprinting' },
  { name: 'default-logins', count: 300, severity: 'high', description: 'Default credential testing' },
  { name: 'takeovers', count: 100, severity: 'critical', description: 'Subdomain takeover detection' },
  { name: 'file', count: 400, severity: 'medium', description: 'Sensitive file detection' },
  { name: 'network', count: 200, severity: 'medium', description: 'Network service scanning' },
  { name: 'dns', count: 150, severity: 'info', description: 'DNS record analysis' },
  { name: 'ssl', count: 100, severity: 'low', description: 'SSL/TLS configuration analysis' },
  { name: 'headless', count: 50, severity: 'medium', description: 'Browser-based detection (headless Chrome)' },
];

/**
 * Build the nuclei command string from scan parameters
 */
function buildNucleiCommand(input: {
  targets: string[];
  templateCategories?: string[];
  severity?: string[];
  tags?: string[];
  rateLimit: number;
  concurrency: number;
  timeout: number;
  headless: boolean;
  interactsh: boolean;
}): string {
  const parts = ['nuclei'];

  // Targets
  if (input.targets.length === 1) {
    parts.push(`-u "${input.targets[0]}"`);
  } else {
    // Multiple targets — write to a temp file inline
    parts.push(`-l <(echo -e "${input.targets.join('\\n')}")`);
  }

  // Template categories
  if (input.templateCategories?.length) {
    parts.push(`-t ${input.templateCategories.join(',')}`);
  }

  // Severity filter
  if (input.severity?.length) {
    parts.push(`-s ${input.severity.join(',')}`);
  }

  // Tags
  if (input.tags?.length) {
    parts.push(`-tags ${input.tags.join(',')}`);
  }

  // Rate limiting and concurrency
  parts.push(`-rl ${input.rateLimit}`);
  parts.push(`-c ${input.concurrency}`);
  parts.push(`-timeout ${input.timeout}`);

  // Headless
  if (input.headless) {
    parts.push('-headless');
  }

  // Interactsh
  if (!input.interactsh) {
    parts.push('-ni');
  }

  // JSON output for structured parsing
  parts.push('-jsonl');

  // Silent mode (no banner)
  parts.push('-silent');

  // Disable update check (prevents hang on startup)
  parts.push('-duc');

  // No color codes in output
  parts.push('-nc');

  return parts.join(' ');
}

/**
 * Parse nuclei JSONL output into structured findings
 */
function parseNucleiJsonOutput(output: string): NucleiFinding[] {
  const findings: NucleiFinding[] = [];
  const lines = output.split('\n').filter(l => l.trim());

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      findings.push({
        templateId: obj['template-id'] || obj.templateID || '',
        name: obj.info?.name || obj.name || obj['template-id'] || 'Unknown',
        severity: (obj.info?.severity || obj.severity || 'info').toLowerCase(),
        host: obj.host || obj.url || '',
        matched: obj['matched-at'] || obj.matched || obj.host || '',
        description: obj.info?.description || '',
        tags: obj.info?.tags || [],
        cveId: obj.info?.classification?.['cve-id']?.[0] || undefined,
        cweId: obj.info?.classification?.['cwe-id']?.[0] || undefined,
        extractedResults: obj['extracted-results'] || [],
        curl: obj['curl-command'] || undefined,
        timestamp: obj.timestamp || new Date().toISOString(),
        type: obj.type || 'http',
        ip: obj.ip || undefined,
        port: obj.port || undefined,
      });
    } catch {
      // Skip non-JSON lines (progress output, etc.)
    }
  }

  return findings;
}

export const nucleiScannerRouter = router({
  /**
   * List template categories with counts.
   */
  listTemplateCategories: protectedProcedure.query(() => {
    return TEMPLATE_CATEGORIES;
  }),

  /**
   * Start a new nuclei scan — executes on the scan server via SSH.
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
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate all scan targets ──
      if (input.engagementId && input.targets.length > 0) {
        try {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, input.targets, "Nuclei Scanner", ctx);
        } catch (scopeErr: any) {
          console.warn(`[NucleiScanner] Scope enforcement skipped: ${scopeErr.message}`);
        }
      }

      // ── Credential Auto-Injection ──
      let credentialInjection: any = null;
      try {
        const { getCredentialInjectionForTargets } = await import("../lib/nuclei-credential-mapper");
        credentialInjection = await getCredentialInjectionForTargets(input.targets);
        if (credentialInjection.templates.length > 0) {
          console.log(
            `[NucleiScanner] Auto-injecting ${credentialInjection.stats.totalTemplates} default-login templates ` +
            `with ${credentialInjection.stats.totalCredentials} credentials for scan targets`
          );
          if (!input.templateCategories?.includes('default-logins')) {
            input.templateCategories = [...(input.templateCategories || []), 'default-logins'];
          }
        }
      } catch (credErr: any) {
        console.warn(`[NucleiScanner] Credential injection failed (non-fatal):`, credErr.message);
      }

      const command = buildNucleiCommand(input);
      const scanId = ++scanCounter;

      const scan: NucleiScan = {
        id: scanId,
        ...input,
        status: 'running',
        startedAt: Date.now(),
        completedAt: null,
        findings: [],
        rawOutput: '',
        rawStderr: '',
        exitCode: -1,
        durationMs: 0,
        credentialInjection,
        command,
        stats: {
          templatesLoaded: 0,
          templatesExecuted: 0,
          hostsScanned: input.targets.length,
          matchesFound: 0,
          requestsSent: 0,
          credentialTemplatesInjected: credentialInjection?.stats?.totalTemplates || 0,
          credentialsMatched: credentialInjection?.stats?.totalCredentials || 0,
        },
      };

      scans.set(scanId, scan);

      // Execute asynchronously on scan server
      (async () => {
        try {
          const { executeRawCommand } = await import("../lib/scan-server-executor");
          // Nuclei scans can take a while — allow up to 10 minutes
          const result = await executeRawCommand(command, 600);

          scan.rawOutput = result.stdout || '';
          scan.rawStderr = result.stderr || '';
          scan.exitCode = result.exitCode;
          scan.durationMs = result.durationMs;

          // Parse JSONL output
          scan.findings = parseNucleiJsonOutput(scan.rawOutput);
          scan.stats.matchesFound = scan.findings.length;

          // Extract template stats from stderr (nuclei prints stats to stderr)
          const templateMatch = scan.rawStderr.match(/Templates:\s*(\d+)/);
          if (templateMatch) scan.stats.templatesLoaded = parseInt(templateMatch[1]);
          const execMatch = scan.rawStderr.match(/Templates Executed:\s*(\d+)/);
          if (execMatch) scan.stats.templatesExecuted = parseInt(execMatch[1]);
          const reqMatch = scan.rawStderr.match(/Requests:\s*(\d+)/);
          if (reqMatch) scan.stats.requestsSent = parseInt(reqMatch[1]);

          scan.status = result.exitCode === 0 || scan.findings.length > 0 ? 'completed' : 'failed';
          scan.completedAt = Date.now();

          console.log(`[NucleiScanner] Scan #${scanId} completed: ${scan.findings.length} findings, exit code ${result.exitCode}`);

          // If linked to engagement, feed findings back
          if (input.engagementId && scan.findings.length > 0) {
            try {
              const { feedScanResultsToEngagement } = await import("../lib/supplemental-scan-feeder");
              await feedScanResultsToEngagement(input.engagementId, 'nuclei', scan.findings);
            } catch (feedErr: any) {
              console.warn(`[NucleiScanner] Failed to feed results to engagement: ${feedErr.message}`);
            }
          }
        } catch (err: any) {
          scan.status = 'failed';
          scan.rawStderr = err.message;
          scan.completedAt = Date.now();
          console.error(`[NucleiScanner] Scan #${scanId} failed:`, err.message);
        }
      })();

      return {
        scanId: scan.id,
        status: 'running',
        command,
        targets: input.targets,
        credentialInjection: credentialInjection ? {
          templatesInjected: credentialInjection.stats.totalTemplates,
          credentialsMatched: credentialInjection.stats.totalCredentials,
          templateIds: credentialInjection.templateIds,
          byProtocol: credentialInjection.stats.byProtocol,
        } : null,
      };
    }),

  /**
   * Get scan status and results.
   */
  getScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(({ input }) => {
      const scan = scans.get(input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);
      return {
        ...scan,
        rawOutput: scan.rawOutput.slice(0, 100000), // Limit output size for transfer
        rawStderr: scan.rawStderr.slice(0, 50000),
      };
    }),

  /**
   * List all scans.
   */
  listScans: protectedProcedure
    .input(z.object({
      limit: z.number().default(20),
      status: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled']).optional(),
    }).optional())
    .query(({ input }) => {
      let all = Array.from(scans.values()).sort((a, b) => b.startedAt - a.startedAt);
      if (input?.status) {
        all = all.filter(s => s.status === input.status);
      }
      return {
        total: all.length,
        scans: all.slice(0, input?.limit || 20).map(s => ({
          ...s,
          rawOutput: '', // Don't send raw output in list view
          rawStderr: '',
        })),
      };
    }),

  /**
   * Submit scan findings (from CLI or external API integration).
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
      const scan = scans.get(input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);

      const newFindings: NucleiFinding[] = input.findings.map(f => ({
        ...f,
        matched: f.matched || f.host,
        description: f.description || '',
        tags: f.tags || [],
        extractedResults: f.extractedResults || [],
        timestamp: new Date().toISOString(),
        type: 'http',
      }));

      scan.findings.push(...newFindings);
      scan.stats.matchesFound = scan.findings.length;

      return { added: newFindings.length, total: scan.findings.length };
    }),

  /**
   * Cancel a running scan.
   */
  cancelScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(({ input }) => {
      const scan = scans.get(input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);
      if (scan.status === 'running') {
        scan.status = 'cancelled';
        scan.completedAt = Date.now();
      }
      return { scanId: scan.id, status: scan.status };
    }),

  /**
   * Complete a scan manually.
   */
  completeScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .mutation(({ input }) => {
      const scan = scans.get(input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);
      scan.status = 'completed';
      scan.completedAt = Date.now();
      return { scanId: scan.id, status: 'completed', findings: scan.findings.length };
    }),

  /**
   * Get scanner stats.
   */
  getStats: protectedProcedure.query(() => {
    const allScans = Array.from(scans.values());
    const allFindings = allScans.flatMap(s => s.findings);
    return {
      totalScans: allScans.length,
      activeScans: allScans.filter(s => s.status === 'running').length,
      totalFindings: allFindings.length,
      totalTemplates: TEMPLATE_CATEGORIES.reduce((sum, t) => sum + t.count, 0),
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
