/**
 * OWASP Coverage Tracker
 * 
 * Tracks which OWASP Top 10:2025 categories were tested per target during
 * an engagement, identifies coverage gaps, and generates coverage reports
 * for inclusion in engagement reports.
 * 
 * Integrates with:
 * - owasp-knowledge.ts for category definitions and finding classification
 * - report-generator.ts for engagement report enrichment
 * - engagement-orchestrator.ts for real-time coverage tracking during scans
 */

import {
  getAllOwaspCategories,
  classifyFindingToOwasp,
  getTestingCommandsForCategory,
  getOwaspPrioritiesForTech,
  type OwaspCategory,
} from "./owasp-knowledge";

// ─── Types ──────────────────────────────────────────────────────────────

export type CoverageStatus = "tested" | "partial" | "not_tested" | "not_applicable";

export interface OwaspCategoryResult {
  categoryId: string;
  categoryName: string;
  status: CoverageStatus;
  findingsCount: number;
  findings: Array<{
    title: string;
    severity: string;
    tool: string;
    description?: string;
  }>;
  toolsUsed: string[];
  /** Why this category was or wasn't tested */
  rationale: string;
}

export interface AssetOwaspCoverage {
  hostname: string;
  ip?: string;
  detectedTech: string[];
  categories: OwaspCategoryResult[];
  coverageScore: number; // 0-100
  testedCount: number;
  partialCount: number;
  gapCount: number;
  notApplicableCount: number;
}

export interface EngagementOwaspCoverage {
  engagementId: string;
  timestamp: string;
  assets: AssetOwaspCoverage[];
  overallScore: number; // 0-100
  totalCategories: number;
  totalTested: number;
  totalPartial: number;
  totalGaps: number;
  totalNotApplicable: number;
  criticalGaps: Array<{
    categoryId: string;
    categoryName: string;
    affectedAssets: string[];
    recommendation: string;
    priority: "critical" | "high" | "medium" | "low";
  }>;
  summaryNarrative: string;
}

export interface ScanFinding {
  title: string;
  description?: string;
  severity: string;
  tool: string;
  target: string; // hostname or IP
}

export interface ScanToolRun {
  tool: string;
  target: string;
  command?: string;
  exitCode?: number;
}

// ─── OWASP Category Metadata ────────────────────────────────────────────

const OWASP_CATEGORY_NAMES: Record<string, string> = {
  "A01:2025": "Broken Access Control",
  "A02:2025": "Security Misconfiguration",
  "A03:2025": "Vulnerable & Outdated Components",
  "A04:2025": "Cryptographic Failures",
  "A05:2025": "Injection",
  "A06:2025": "Insecure Design",
  "A07:2025": "Identification & Authentication Failures",
  "A08:2025": "Software & Data Integrity Failures",
  "A09:2025": "Security Logging & Monitoring Failures",
  "A10:2025": "Server-Side Request Forgery (SSRF)",
};

/** Tools that test specific OWASP categories */
const TOOL_TO_OWASP_COVERAGE: Record<string, string[]> = {
  // Injection tools
  sqlmap: ["A05:2025"],
  "nuclei -tags sqli": ["A05:2025"],
  "nuclei -tags xss": ["A05:2025"],
  "nuclei -tags ssti": ["A05:2025"],
  "nuclei -tags xxe": ["A05:2025"],
  commix: ["A05:2025"],
  
  // Access control tools
  feroxbuster: ["A01:2025"],
  gobuster: ["A01:2025"],
  dirbuster: ["A01:2025"],
  "nuclei -tags idor": ["A01:2025"],
  "nuclei -tags lfi": ["A01:2025"],
  "nuclei -tags rfi": ["A01:2025"],
  
  // Misconfiguration tools
  nikto: ["A02:2025", "A04:2025"],
  "nuclei -tags misconfig": ["A02:2025"],
  "nuclei -tags default-login": ["A02:2025"],
  "nuclei -tags exposure": ["A02:2025"],
  "nuclei -tags config": ["A02:2025"],
  "http-security-headers": ["A02:2025"],
  
  // Component analysis
  "nuclei -tags cve": ["A03:2025"],
  "nuclei -tags tech": ["A03:2025"],
  nmap: ["A03:2025", "A04:2025"],
  
  // Crypto tools
  "ssl-enum-ciphers": ["A04:2025"],
  testssl: ["A04:2025"],
  sslscan: ["A04:2025"],
  
  // Auth tools
  hydra: ["A07:2025"],
  "nuclei -tags login": ["A07:2025"],
  "nuclei -tags auth-bypass": ["A07:2025"],
  
  // Integrity tools
  ysoserial: ["A08:2025"],
  "nuclei -tags deserialization": ["A08:2025"],
  
  // SSRF tools
  "nuclei -tags ssrf": ["A10:2025"],
  
  // Cloud tools (cover multiple categories)
  cloud_enum: ["A02:2025", "A01:2025"],
  s3scanner: ["A01:2025", "A02:2025"],
  
  // General web scanners cover multiple
  nuclei: ["A02:2025", "A03:2025", "A05:2025"],
  zap: ["A01:2025", "A02:2025", "A05:2025", "A07:2025"],
  burpsuite: ["A01:2025", "A02:2025", "A05:2025", "A07:2025"],
};

// ─── Coverage Tracker Class ─────────────────────────────────────────────

export class OwaspCoverageTracker {
  private findings: ScanFinding[] = [];
  private toolRuns: ScanToolRun[] = [];
  private assetTech: Map<string, string[]> = new Map();

  /**
   * Register detected technologies for an asset
   */
  registerAssetTech(hostname: string, technologies: string[]): void {
    const existing = this.assetTech.get(hostname) || [];
    this.assetTech.set(hostname, [...new Set([...existing, ...technologies])]);
  }

  /**
   * Record a scan finding
   */
  addFinding(finding: ScanFinding): void {
    this.findings.push(finding);
  }

  /**
   * Record a tool execution
   */
  addToolRun(run: ScanToolRun): void {
    this.toolRuns.push(run);
  }

  /**
   * Bulk import findings from engagement ops data
   */
  importFromEngagementOps(opsData: {
    assets: Array<{
      hostname: string;
      ip?: string;
      passiveRecon?: { technologies?: string[] };
      toolResults?: Array<{
        tool: string;
        command?: string;
        exitCode?: number;
        findings?: string[];
      }>;
    }>;
  }): void {
    for (const asset of opsData.assets) {
      // Register tech
      if (asset.passiveRecon?.technologies) {
        this.registerAssetTech(asset.hostname, asset.passiveRecon.technologies);
      }

      // Import tool runs and findings
      if (asset.toolResults) {
        for (const tr of asset.toolResults) {
          this.addToolRun({
            tool: tr.tool,
            target: asset.hostname,
            command: tr.command,
            exitCode: tr.exitCode,
          });

          if (tr.findings) {
            for (const f of tr.findings) {
              this.addFinding({
                title: f,
                severity: "info",
                tool: tr.tool,
                target: asset.hostname,
              });
            }
          }
        }
      }
    }
  }

  /**
   * Generate per-asset OWASP coverage analysis
   */
  getAssetCoverage(hostname: string): AssetOwaspCoverage {
    const tech = this.assetTech.get(hostname) || [];
    const assetFindings = this.findings.filter(f => f.target === hostname);
    const assetToolRuns = this.toolRuns.filter(r => r.target === hostname);
    const toolsUsedSet = new Set(assetToolRuns.map(r => r.tool));

    const categories: OwaspCategoryResult[] = [];

    for (const [catId, catName] of Object.entries(OWASP_CATEGORY_NAMES)) {
      // Classify findings into this category
      const catFindings = assetFindings.filter(f => {
        const classified = classifyFindingToOwasp(f.title, f.description);
        return classified === catId;
      });

      // Check which tools covered this category
      const coveringTools: string[] = [];
      for (const [toolPattern, coveredCats] of Object.entries(TOOL_TO_OWASP_COVERAGE)) {
        if (!coveredCats.includes(catId)) continue;
        // Check if any tool run matches this pattern
        for (const run of assetToolRuns) {
          const runStr = `${run.tool} ${run.command || ""}`.toLowerCase();
          const patternLower = toolPattern.toLowerCase();
          if (runStr.includes(patternLower) || run.tool.toLowerCase().includes(patternLower.split(" ")[0])) {
            coveringTools.push(run.tool);
            break;
          }
        }
      }

      // Determine status
      let status: CoverageStatus;
      let rationale: string;

      if (catFindings.length > 0 && coveringTools.length > 0) {
        status = "tested";
        rationale = `${coveringTools.length} tool(s) tested this category, ${catFindings.length} finding(s) discovered.`;
      } else if (coveringTools.length > 0) {
        status = "tested";
        rationale = `${coveringTools.length} tool(s) tested this category, no findings discovered (clean).`;
      } else if (catFindings.length > 0) {
        status = "partial";
        rationale = `Findings classified under this category exist but no dedicated tool was run for systematic testing.`;
      } else {
        // Check if the category is applicable based on tech stack
        const techPriorities = tech.flatMap(t => getOwaspPrioritiesForTech(t));
        const isRelevant = techPriorities.some(p => p.id === catId);
        
        if (!isRelevant && tech.length > 0) {
          status = "not_applicable";
          rationale = `Category not relevant to detected technology stack (${tech.join(", ")}).`;
        } else {
          status = "not_tested";
          const commands = getTestingCommandsForCategory(catId);
          const suggestedTools = commands.slice(0, 3).map(c => c.tool).join(", ");
          rationale = `No tools tested this category. Recommended: ${suggestedTools || "manual review"}.`;
        }
      }

      categories.push({
        categoryId: catId,
        categoryName: catName,
        status,
        findingsCount: catFindings.length,
        findings: catFindings.map(f => ({
          title: f.title,
          severity: f.severity,
          tool: f.tool,
          description: f.description,
        })),
        toolsUsed: [...new Set(coveringTools)],
        rationale,
      });
    }

    const testedCount = categories.filter(c => c.status === "tested").length;
    const partialCount = categories.filter(c => c.status === "partial").length;
    const gapCount = categories.filter(c => c.status === "not_tested").length;
    const notApplicableCount = categories.filter(c => c.status === "not_applicable").length;
    const applicableCount = 10 - notApplicableCount;
    const coverageScore = applicableCount > 0
      ? Math.round(((testedCount + partialCount * 0.5) / applicableCount) * 100)
      : 100;

    return {
      hostname,
      ip: undefined,
      detectedTech: tech,
      categories,
      coverageScore,
      testedCount,
      partialCount,
      gapCount,
      notApplicableCount,
    };
  }

  /**
   * Generate full engagement OWASP coverage report
   */
  getEngagementCoverage(engagementId: string): EngagementOwaspCoverage {
    const hostnames = new Set([
      ...this.findings.map(f => f.target),
      ...this.toolRuns.map(r => r.target),
      ...this.assetTech.keys(),
    ]);

    const assets = [...hostnames].map(h => this.getAssetCoverage(h));

    const totalTested = assets.reduce((s, a) => s + a.testedCount, 0);
    const totalPartial = assets.reduce((s, a) => s + a.partialCount, 0);
    const totalGaps = assets.reduce((s, a) => s + a.gapCount, 0);
    const totalNA = assets.reduce((s, a) => s + a.notApplicableCount, 0);
    const totalCategories = assets.length * 10;
    const overallScore = assets.length > 0
      ? Math.round(assets.reduce((s, a) => s + a.coverageScore, 0) / assets.length)
      : 0;

    // Identify critical gaps (categories not tested on ANY asset)
    const gapMap = new Map<string, string[]>();
    for (const asset of assets) {
      for (const cat of asset.categories) {
        if (cat.status === "not_tested") {
          const existing = gapMap.get(cat.categoryId) || [];
          existing.push(asset.hostname);
          gapMap.set(cat.categoryId, existing);
        }
      }
    }

    const criticalGaps = [...gapMap.entries()].map(([catId, affectedAssets]) => {
      const catName = OWASP_CATEGORY_NAMES[catId] || catId;
      const commands = getTestingCommandsForCategory(catId);
      const suggestedTools = commands.slice(0, 3).map(c => `${c.tool}: ${c.command}`).join("; ");
      
      // Priority based on OWASP ranking and number of affected assets
      const catNum = parseInt(catId.replace("A", "").split(":")[0]);
      let priority: "critical" | "high" | "medium" | "low";
      if (catNum <= 3 && affectedAssets.length === assets.length) priority = "critical";
      else if (catNum <= 5) priority = "high";
      else if (catNum <= 7) priority = "medium";
      else priority = "low";

      return {
        categoryId: catId,
        categoryName: catName,
        affectedAssets,
        recommendation: `Run ${suggestedTools || "manual testing"} against ${affectedAssets.join(", ")} to cover ${catName}.`,
        priority,
      };
    }).sort((a, b) => {
      const pOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return pOrder[a.priority] - pOrder[b.priority];
    });

    // Generate summary narrative
    const summaryNarrative = generateCoverageNarrative(
      overallScore, totalTested, totalGaps, totalPartial, assets.length, criticalGaps
    );

    return {
      engagementId,
      timestamp: new Date().toISOString(),
      assets,
      overallScore,
      totalCategories,
      totalTested,
      totalPartial,
      totalGaps,
      totalNotApplicable: totalNA,
      criticalGaps,
      summaryNarrative,
    };
  }

  /**
   * Reset tracker for a new engagement
   */
  reset(): void {
    this.findings = [];
    this.toolRuns = [];
    this.assetTech.clear();
  }
}

// ─── Narrative Generator ────────────────────────────────────────────────

function generateCoverageNarrative(
  score: number,
  tested: number,
  gaps: number,
  partial: number,
  assetCount: number,
  criticalGaps: EngagementOwaspCoverage["criticalGaps"]
): string {
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  
  let narrative = `OWASP Top 10:2025 Coverage Assessment — Grade ${grade} (${score}%)\n\n`;
  narrative += `Across ${assetCount} target asset(s), ${tested} OWASP category-asset combinations were fully tested, `;
  narrative += `${partial} were partially covered, and ${gaps} remain untested.\n\n`;

  if (criticalGaps.length === 0) {
    narrative += `All applicable OWASP categories were tested across all assets. `;
    narrative += `The engagement achieved comprehensive web application security coverage.\n`;
  } else {
    const critCount = criticalGaps.filter(g => g.priority === "critical").length;
    const highCount = criticalGaps.filter(g => g.priority === "high").length;
    
    if (critCount > 0) {
      narrative += `WARNING: ${critCount} critical coverage gap(s) identified — `;
      narrative += criticalGaps.filter(g => g.priority === "critical")
        .map(g => g.categoryName).join(", ");
      narrative += ` — were not tested on any asset. These are high-priority OWASP categories that should be addressed immediately.\n\n`;
    }
    if (highCount > 0) {
      narrative += `${highCount} high-priority gap(s) also identified: `;
      narrative += criticalGaps.filter(g => g.priority === "high")
        .map(g => g.categoryName).join(", ");
      narrative += `.\n\n`;
    }

    narrative += `Recommended remediation:\n`;
    for (const gap of criticalGaps.slice(0, 5)) {
      narrative += `- [${gap.priority.toUpperCase()}] ${gap.categoryName}: ${gap.recommendation}\n`;
    }
  }

  return narrative;
}

// ─── Report Integration Helpers ─────────────────────────────────────────

/**
 * Generate OWASP coverage HTML section for inclusion in engagement reports.
 * Follows the report template privacy requirement — no customer-specific data in the template.
 */
export function renderOwaspCoverageHTML(coverage: EngagementOwaspCoverage): string {
  const statusColors: Record<CoverageStatus, string> = {
    tested: "#22c55e",
    partial: "#f59e0b",
    not_tested: "#ef4444",
    not_applicable: "#6b7280",
  };

  const statusLabels: Record<CoverageStatus, string> = {
    tested: "Tested",
    partial: "Partial",
    not_tested: "Gap",
    not_applicable: "N/A",
  };

  let html = `
    <div class="owasp-coverage-section">
      <h2>OWASP Top 10:2025 Coverage Analysis</h2>
      <div class="coverage-summary">
        <div class="score-badge" style="background: ${coverage.overallScore >= 80 ? '#22c55e' : coverage.overallScore >= 60 ? '#f59e0b' : '#ef4444'}; color: white; padding: 12px 24px; border-radius: 8px; display: inline-block; font-size: 24px; font-weight: bold;">
          ${coverage.overallScore}% Coverage
        </div>
        <p style="margin-top: 8px; color: #6b7280;">
          ${coverage.totalTested} tested | ${coverage.totalPartial} partial | ${coverage.totalGaps} gaps | ${coverage.totalNotApplicable} N/A
        </p>
      </div>`;

  // Per-asset coverage matrix
  for (const asset of coverage.assets) {
    html += `
      <h3>${asset.hostname}${asset.ip ? ` (${asset.ip})` : ''}</h3>
      <p style="color: #6b7280; font-size: 14px;">Tech: ${asset.detectedTech.join(', ') || 'Unknown'} | Score: ${asset.coverageScore}%</p>
      <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
        <thead>
          <tr style="background: #f8fafc;">
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #e2e8f0;">Category</th>
            <th style="padding: 8px; text-align: center; border-bottom: 2px solid #e2e8f0;">Status</th>
            <th style="padding: 8px; text-align: center; border-bottom: 2px solid #e2e8f0;">Findings</th>
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #e2e8f0;">Tools</th>
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #e2e8f0;">Notes</th>
          </tr>
        </thead>
        <tbody>`;

    for (const cat of asset.categories) {
      html += `
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: 500;">${cat.categoryId} ${cat.categoryName}</td>
            <td style="padding: 8px; text-align: center; border-bottom: 1px solid #e2e8f0;">
              <span style="background: ${statusColors[cat.status]}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">
                ${statusLabels[cat.status]}
              </span>
            </td>
            <td style="padding: 8px; text-align: center; border-bottom: 1px solid #e2e8f0;">${cat.findingsCount}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-size: 13px;">${cat.toolsUsed.join(', ') || '—'}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #6b7280;">${cat.rationale}</td>
          </tr>`;
    }

    html += `
        </tbody>
      </table>`;
  }

  // Critical gaps section
  if (coverage.criticalGaps.length > 0) {
    html += `
      <h3 style="color: #ef4444;">Coverage Gaps Requiring Attention</h3>
      <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
        <thead>
          <tr style="background: #fef2f2;">
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #fecaca;">Priority</th>
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #fecaca;">Category</th>
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #fecaca;">Affected Assets</th>
            <th style="padding: 8px; text-align: left; border-bottom: 2px solid #fecaca;">Recommendation</th>
          </tr>
        </thead>
        <tbody>`;

    for (const gap of coverage.criticalGaps) {
      const prioColor = gap.priority === "critical" ? "#dc2626" : gap.priority === "high" ? "#ea580c" : gap.priority === "medium" ? "#d97706" : "#6b7280";
      html += `
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #fecaca;">
              <span style="color: ${prioColor}; font-weight: bold; text-transform: uppercase;">${gap.priority}</span>
            </td>
            <td style="padding: 8px; border-bottom: 1px solid #fecaca;">${gap.categoryId} ${gap.categoryName}</td>
            <td style="padding: 8px; border-bottom: 1px solid #fecaca; font-size: 13px;">${gap.affectedAssets.join(', ')}</td>
            <td style="padding: 8px; border-bottom: 1px solid #fecaca; font-size: 13px;">${gap.recommendation}</td>
          </tr>`;
    }

    html += `
        </tbody>
      </table>`;
  }

  html += `
      <div class="coverage-narrative" style="margin-top: 16px; padding: 16px; background: #f8fafc; border-radius: 8px; white-space: pre-line;">
        ${coverage.summaryNarrative}
      </div>
    </div>`;

  return html;
}

/**
 * Generate OWASP coverage data for inclusion in ReportData.
 * Returns a section that can be added to the report's sections array.
 */
export function generateOwaspReportSection(coverage: EngagementOwaspCoverage): {
  title: string;
  content: string;
} {
  return {
    title: "OWASP Top 10:2025 Coverage Analysis",
    content: coverage.summaryNarrative,
  };
}

// ─── Singleton Instance ─────────────────────────────────────────────────

let _tracker: OwaspCoverageTracker | null = null;

export function getOwaspTracker(): OwaspCoverageTracker {
  if (!_tracker) _tracker = new OwaspCoverageTracker();
  return _tracker;
}

export function resetOwaspTracker(): OwaspCoverageTracker {
  _tracker = new OwaspCoverageTracker();
  return _tracker;
}
