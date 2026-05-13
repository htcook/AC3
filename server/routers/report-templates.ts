import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const reportTemplatesRouter = router({
  list: protectedProcedure
    .input(z.object({ templateType: z.enum(["engagement", "executive", "compliance", "vulnerability", "custom"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq } = await import("drizzle-orm");
      if (input.templateType) {
        return db.select().from(reportTemplates).where(eq(reportTemplates.templateType, input.templateType)).orderBy(desc(reportTemplates.createdAt));
      }
      return db.select().from(reportTemplates).orderBy(desc(reportTemplates.createdAt));
    }),
  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      return result[0];
    }),
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string().optional(),
      templateType: z.enum(["engagement", "executive", "compliance", "vulnerability", "custom"]),
      templateContent: z.string(),
      headerHtml: z.string().optional(),
      footerHtml: z.string().optional(),
      cssOverrides: z.string().optional(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const result = await db.insert(reportTemplates).values({ ...input, createdBy: String(ctx.user.id) });
      return { id: result[0].insertId };
    }),
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      description: z.string().optional(),
      templateContent: z.string().optional(),
      headerHtml: z.string().optional(),
      footerHtml: z.string().optional(),
      cssOverrides: z.string().optional(),
      logoUrl: z.string().optional(),
      primaryColor: z.string().optional(),
      isDefault: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { id, ...updates } = input;
      await db.update(reportTemplates).set(updates).where(eq(reportTemplates.id, id));
      return { success: true };
    }),
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(reportTemplates).where(eq(reportTemplates.id, input.id));
      return { success: true };
    }),
  duplicate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const original = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!original[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      const { id: _id, createdAt: _ca, updatedAt: _ua, ...rest } = original[0];
      const result = await db.insert(reportTemplates).values({
        ...rest,
        name: `${rest.name} (Copy)`,
        isDefault: false,
        createdBy: String(ctx.user.id),
      });
      return { id: result[0].insertId };
    }),
  renderPreview: protectedProcedure
    .input(z.object({ id: z.number(), sampleData: z.record(z.string(), z.any()) }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { reportTemplates } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const template = await db.select().from(reportTemplates).where(eq(reportTemplates.id, input.id));
      if (!template[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Report template not found" });
      let renderedContent = template[0].templateContent;
      for (const key in input.sampleData) {
        const value = input.sampleData[key];
        renderedContent = renderedContent.replace(new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, "g"), String(value));
      }
      return { html: renderedContent };
    }),

  /** Get available data sources for template preview */
  getPreviewSources: protectedProcedure
    .query(async () => {
      const { getDb } = await import("../db");
      const { domainIntelScans, engagements } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq, or } = await import("drizzle-orm");

      // Get recent DI scans
      const diScans = await db.select({
        id: domainIntelScans.id,
        primaryDomain: domainIntelScans.primaryDomain,
        totalAssets: domainIntelScans.totalAssets,
        totalFindings: domainIntelScans.totalFindings,
        overallRiskScore: domainIntelScans.overallRiskScore,
        createdAt: domainIntelScans.createdAt,
      }).from(domainIntelScans)
        .where(or(eq(domainIntelScans.status, 'completed'), eq(domainIntelScans.status, 'scan_complete'))!)
        .orderBy(desc(domainIntelScans.createdAt))
        .limit(10);

      // Get recent engagements
      const engs = await db.select({
        id: engagements.id,
        name: engagements.name,
        customerName: engagements.customerName,
        engagementType: engagements.engagementType,
        targetDomain: engagements.targetDomain,
        createdAt: engagements.createdAt,
      }).from(engagements)
        .orderBy(desc(engagements.createdAt))
        .limit(10);

      return {
        diScans: diScans.map(s => ({
          id: s.id,
          label: `DI: ${s.primaryDomain} (Score: ${s.overallRiskScore || 0}, ${s.totalAssets || 0} assets)`,
          type: 'di' as const,
          domain: s.primaryDomain,
          createdAt: s.createdAt,
        })),
        engagements: engs.map(e => ({
          id: e.id,
          label: `${e.engagementType?.replace('_', ' ')}: ${e.name} (${e.customerName})`,
          type: 'engagement' as const,
          domain: e.targetDomain,
          createdAt: e.createdAt,
        })),
      };
    }),

  /** Fetch real data from a DI scan or engagement for template preview */
  getPreviewData: protectedProcedure
    .input(z.object({
      sourceType: z.enum(['di', 'engagement']),
      sourceId: z.number(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      if (input.sourceType === 'di') {
        const { domainIntelScans, discoveredAssets } = await import("../../drizzle/schema");
        const scan = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.sourceId));
        if (!scan[0]) throw new TRPCError({ code: "NOT_FOUND", message: "DI scan not found" });
        const s = scan[0];

        // Get discovered assets for this scan
        const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.sourceId)).limit(50);

        // Parse pipeline output for findings breakdown
        const pipelineOutput = (s.pipelineOutput as any) || {};
        const findings = pipelineOutput.findings || pipelineOutput.vulnFindings || [];
        const criticalFindings = Array.isArray(findings) ? findings.filter((f: any) => f.severity === 'critical' || f.cvssScore >= 9).length : (s.confirmedFindings || 0);
        const highFindings = Array.isArray(findings) ? findings.filter((f: any) => f.severity === 'high' || (f.cvssScore >= 7 && f.cvssScore < 9)).length : 0;
        const mediumFindings = Array.isArray(findings) ? findings.filter((f: any) => f.severity === 'medium' || (f.cvssScore >= 4 && f.cvssScore < 7)).length : 0;
        const lowFindings = Array.isArray(findings) ? findings.filter((f: any) => f.severity === 'low' || (f.cvssScore > 0 && f.cvssScore < 4)).length : 0;

        // Build subdomains table HTML
        const subdomainsHtml = `<table><thead><tr><th>Hostname</th><th>Type</th><th>Status</th></tr></thead><tbody>${
          assets.slice(0, 20).map(a => `<tr><td>${a.hostname}</td><td>${a.assetType || 'subdomain'}</td><td>${a.dnsStatus || 'active'}</td></tr>`).join('')
        }</tbody></table>`;

        // Build technologies table HTML
        const techSet = new Set<string>();
        assets.forEach(a => {
          const techs = (a.technologies as any[]) || [];
          techs.forEach(t => techSet.add(typeof t === 'string' ? t : t?.name || ''));
        });
        const techsHtml = `<table><thead><tr><th>Technology</th><th>Category</th></tr></thead><tbody>${
          Array.from(techSet).slice(0, 20).map(t => `<tr><td>${t}</td><td>Detected</td></tr>`).join('')
        }</tbody></table>`;

        return {
          client_name: s.sector || 'Client Organization',
          report_date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
          report_title: `Domain Intelligence Report — ${s.primaryDomain}`,
          assessor_name: 'AceofCloud Security',
          engagement_id: `DI-${s.id}`,
          scope: `Domain intelligence scan of ${s.primaryDomain}${s.additionalDomains ? ' and related domains' : ''}`,
          executive_summary: s.executiveSummary || `A comprehensive domain intelligence scan was performed against ${s.primaryDomain}. The scan identified ${s.totalAssets || 0} assets with an overall risk score of ${s.overallRiskScore || 0}/100.`,
          methodology: 'OSINT, DNS enumeration, certificate transparency, passive reconnaissance, technology fingerprinting',
          recommendations: s.campaignRecommendations ? JSON.stringify(s.campaignRecommendations) : 'Review and remediate findings by severity priority.',
          domain: s.primaryDomain,
          total_assets: String(s.totalAssets || 0),
          risk_score: String(s.overallRiskScore || 0),
          critical_findings: String(criticalFindings),
          high_findings: String(highFindings),
          medium_findings: String(mediumFindings),
          low_findings: String(lowFindings),
          total_vulns: String(s.totalFindings || 0),
          critical_count: String(criticalFindings),
          high_count: String(highFindings),
          medium_count: String(mediumFindings),
          low_count: String(lowFindings),
          recon_coverage: `${s.discoveryCoverageScore || 0}%`,
          subdomains_table: subdomainsHtml,
          technologies_table: techsHtml,
          certificates_table: '<table><thead><tr><th>Domain</th><th>Issuer</th><th>Expiry</th></tr></thead><tbody><tr><td colspan="3">Certificate data available in full report</td></tr></tbody></table>',
          dns_records_table: '<table><thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead><tbody><tr><td colspan="3">DNS records available in full report</td></tr></tbody></table>',
        };
      } else {
        // Engagement data
        const { engagements, scanResults } = await import("../../drizzle/schema");
        const eng = await db.select().from(engagements).where(eq(engagements.id, input.sourceId));
        if (!eng[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
        const e = eng[0];

        // Get scan results for this engagement
        let vulns: any[] = [];
        try {
          vulns = await db.select().from(scanResults).where(eq(scanResults.engagementId, input.sourceId)).limit(100);
        } catch { /* scanResults table may not exist */ }

        const criticalCount = vulns.filter(v => v.severity === 'critical').length;
        const highCount = vulns.filter(v => v.severity === 'high').length;
        const mediumCount = vulns.filter(v => v.severity === 'medium').length;
        const lowCount = vulns.filter(v => v.severity === 'low').length;

        // Build vulnerabilities table
        const vulnsHtml = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th></tr></thead><tbody>${
          vulns.slice(0, 20).map((v, i) => `<tr><td>V-${String(i+1).padStart(3,'0')}</td><td>${v.title || v.templateId || 'Finding'}</td><td class="severity-${v.severity}">${(v.severity || 'info').toUpperCase()}</td><td>${v.cvssScore || '-'}</td></tr>`).join('')
        }</tbody></table>`;

        const cvssScores = vulns.filter(v => v.cvssScore).map(v => v.cvssScore);
        const cvssAvg = cvssScores.length > 0 ? (cvssScores.reduce((a: number, b: number) => a + b, 0) / cvssScores.length).toFixed(1) : '0';
        const cvssMax = cvssScores.length > 0 ? Math.max(...cvssScores).toFixed(1) : '0';

        return {
          client_name: e.customerName,
          report_date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
          report_title: `${e.engagementType?.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())} Report — ${e.name}`,
          assessor_name: 'AceofCloud Security',
          engagement_id: `ENG-${e.id}`,
          scope: `${e.engagementType?.replace('_', ' ')} engagement targeting ${e.targetDomain || e.targetIpRange || 'specified scope'}`,
          executive_summary: e.description || `A ${e.engagementType?.replace('_', ' ')} engagement was conducted against ${e.targetDomain || 'the target environment'}. ${vulns.length} vulnerabilities were identified.`,
          methodology: e.engagementType === 'red_team' ? 'MITRE ATT&CK, PTES, custom TTPs' : e.engagementType === 'pentest' ? 'OWASP, PTES, NIST SP 800-115' : 'Industry standard methodology',
          recommendations: 'Remediate critical and high findings immediately. Implement defense-in-depth controls.',
          domain: e.targetDomain || '',
          total_vulns: String(vulns.length),
          critical_count: String(criticalCount),
          high_count: String(highCount),
          medium_count: String(mediumCount),
          low_count: String(lowCount),
          cvss_avg: cvssAvg,
          cvss_max: cvssMax,
          vulnerabilities_table: vulnsHtml,
          affected_hosts_table: '<table><thead><tr><th>Host</th><th>Findings</th><th>Risk</th></tr></thead><tbody><tr><td colspan="3">Host data available in full report</td></tr></tbody></table>',
          remediation_priority: 'Address critical vulnerabilities first, then high severity findings.',
          exploits_attempted: String(vulns.length),
          exploits_successful: String(criticalCount + highCount),
          credentials_found: '0',
          attack_path: 'See detailed findings for attack path analysis.',
          initial_access: e.engagementType === 'red_team' ? 'Phishing / External exploitation' : 'Network scanning and enumeration',
          privilege_escalation: 'See detailed findings.',
          lateral_movement: 'See detailed findings.',
          data_exfiltration: 'See detailed findings.',
          findings_table: vulnsHtml,
          timeline_table: '<table><thead><tr><th>Time</th><th>Action</th><th>Result</th></tr></thead><tbody><tr><td colspan="3">Timeline data available in full report</td></tr></tbody></table>',
          objectives: 'Assess security posture and identify vulnerabilities',
          objectives_achieved: `${criticalCount + highCount > 0 ? 'Critical access achieved' : 'Partial objectives met'}`,
          detection_rate: '0%',
          dwell_time: 'N/A',
          ttps_used: 'See MITRE ATT&CK mapping in full report',
          initial_access_vector: e.engagementType === 'red_team' ? 'Phishing / External exploitation' : 'Network scanning',
          persistence_mechanisms: 'See detailed findings.',
          c2_infrastructure: 'See detailed findings.',
          evasion_techniques: 'See detailed findings.',
          impact_assessment: `${criticalCount} critical and ${highCount} high severity findings identified.`,
          blue_team_response: 'See detection analysis in full report.',
          attack_narrative: e.description || 'See full engagement report for attack narrative.',
        };
      }
    }),
});
