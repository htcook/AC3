import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import {
  OwaspCoverageTracker,
  getOwaspTracker,
  resetOwaspTracker,
  generateOwaspReportSection,
  renderOwaspCoverageHTML,
} from "../lib/owasp-coverage-tracker";

export const owaspCoverageRouter = router({
  /** Get OWASP coverage for an engagement from its ops state */
  getEngagementCoverage: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import(
        "../lib/engagement-orchestrator"
      );

      let state = getOpsState(input.engagementId);
      if (!state) {
        state = await getOpsStateWithRecovery(input.engagementId);
      }
      if (!state) {
        return null;
      }

      // Build a fresh tracker from the ops state
      const tracker = new OwaspCoverageTracker();

      for (const asset of state.assets) {
        // Register detected technologies
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) tracker.registerAssetTech(asset.hostname, tech);

        // Register all tool runs and findings
        for (const tr of asset.toolResults) {
          tracker.addToolRun({
            tool: tr.tool,
            target: asset.hostname,
            command: tr.command,
            exitCode: tr.exitCode,
          });
          for (const f of tr.findings) {
            tracker.addFinding({
              title: f.title,
              severity: f.severity,
              tool: tr.tool,
              target: asset.hostname,
            });
          }
        }

        // Register vuln findings
        for (const v of asset.vulns) {
          tracker.addFinding({
            title: v.title,
            severity: v.severity,
            tool: "nuclei",
            target: asset.hostname,
          });
        }

        // Register ZAP findings
        for (const z of asset.zapFindings) {
          tracker.addFinding({
            title: z.alert,
            severity: z.risk,
            tool: "zap",
            target: asset.hostname,
          });
        }
      }

      const coverage = tracker.getEngagementCoverage(
        String(input.engagementId)
      );
      return coverage;
    }),

  /** Export OWASP coverage as CSV data */
  exportCsv: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import(
        "../lib/engagement-orchestrator"
      );

      let state = getOpsState(input.engagementId);
      if (!state) {
        state = await getOpsStateWithRecovery(input.engagementId);
      }
      if (!state) {
        return { csv: "", filename: "" };
      }

      // Build tracker from ops state
      const tracker = new OwaspCoverageTracker();
      for (const asset of state.assets) {
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) tracker.registerAssetTech(asset.hostname, tech);
        for (const tr of asset.toolResults) {
          tracker.addToolRun({
            tool: tr.tool,
            target: asset.hostname,
            command: tr.command,
            exitCode: tr.exitCode,
          });
          for (const f of tr.findings) {
            tracker.addFinding({
              title: f.title,
              severity: f.severity,
              tool: tr.tool,
              target: asset.hostname,
            });
          }
        }
        for (const v of asset.vulns) {
          tracker.addFinding({
            title: v.title,
            severity: v.severity,
            tool: "nuclei",
            target: asset.hostname,
          });
        }
        for (const z of asset.zapFindings) {
          tracker.addFinding({
            title: z.alert,
            severity: z.risk,
            tool: "zap",
            target: asset.hostname,
          });
        }
      }

      const coverage = tracker.getEngagementCoverage(
        String(input.engagementId)
      );

      // Build CSV
      const rows: string[] = [];
      rows.push(
        [
          "OWASP Category ID",
          "Category Name",
          "Status",
          "Score (%)",
          "Findings Count",
          "Tools Used",
          "Gap Analysis",
        ].join(",")
      );

      for (const cat of coverage.categories) {
        rows.push(
          [
            `"${cat.id}"`,
            `"${cat.name}"`,
            `"${cat.status}"`,
            cat.score,
            cat.findingsCount,
            `"${(cat.toolsCovering || []).join("; ")}"`,
            `"${(cat.gapAnalysis || "").replace(/"/g, '""')}"`,
          ].join(",")
        );
      }

      // Per-asset breakdown
      rows.push("");
      rows.push("Per-Asset Coverage Matrix");
      rows.push(
        ["Asset", "OWASP Category", "Status", "Score", "Findings"].join(",")
      );

      for (const assetCov of coverage.assetCoverage || []) {
        for (const cat of assetCov.categories) {
          rows.push(
            [
              `"${assetCov.asset}"`,
              `"${cat.id}: ${cat.name}"`,
              `"${cat.status}"`,
              cat.score,
              cat.findingsCount,
            ].join(",")
          );
        }
      }

      // Summary
      rows.push("");
      rows.push(`Overall Score,${coverage.overallScore}%`);
      rows.push(`Grade,${coverage.grade}`);
      rows.push(`Tested,${coverage.totalTested}`);
      rows.push(`Partial,${coverage.totalPartial}`);
      rows.push(`Gaps,${coverage.totalGaps}`);

      const csv = rows.join("\n");
      const filename = `owasp-coverage-engagement-${input.engagementId}-${new Date().toISOString().slice(0, 10)}.csv`;

      return { csv, filename };
    }),

  /** Export OWASP coverage as HTML report section */
  exportHtml: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import(
        "../lib/engagement-orchestrator"
      );

      let state = getOpsState(input.engagementId);
      if (!state) {
        state = await getOpsStateWithRecovery(input.engagementId);
      }
      if (!state) {
        return { html: "", filename: "" };
      }

      // Build tracker from ops state
      const tracker = new OwaspCoverageTracker();
      for (const asset of state.assets) {
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) tracker.registerAssetTech(asset.hostname, tech);
        for (const tr of asset.toolResults) {
          tracker.addToolRun({
            tool: tr.tool,
            target: asset.hostname,
            command: tr.command,
            exitCode: tr.exitCode,
          });
          for (const f of tr.findings) {
            tracker.addFinding({
              title: f.title,
              severity: f.severity,
              tool: tr.tool,
              target: asset.hostname,
            });
          }
        }
        for (const v of asset.vulns) {
          tracker.addFinding({
            title: v.title,
            severity: v.severity,
            tool: "nuclei",
            target: asset.hostname,
          });
        }
        for (const z of asset.zapFindings) {
          tracker.addFinding({
            title: z.alert,
            severity: z.risk,
            tool: "zap",
            target: asset.hostname,
          });
        }
      }

      const coverage = tracker.getEngagementCoverage(
        String(input.engagementId)
      );
      const html = renderOwaspCoverageHTML(coverage);
      const filename = `owasp-coverage-engagement-${input.engagementId}-${new Date().toISOString().slice(0, 10)}.html`;

      return { html, filename };
    }),
});
