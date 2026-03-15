/**
 * Executive Dashboard PDF Export
 *
 * Generates a professional, board-ready PDF report from the Executive Dashboard data.
 * Includes KPIs, risk posture, MITRE ATT&CK coverage, C2 readiness, engagement metrics,
 * and automation pipeline status.
 *
 * Author: Harrison Cook — AceofCloud
 */

// Dynamic imports for jsPDF and autoTable
async function loadPdfLibs() {
  const jsPDFModule = await import("jspdf");
  const autoTableModule = await import("jspdf-autotable");
  return {
    jsPDF: jsPDFModule.default || jsPDFModule.jsPDF,
    autoTable: autoTableModule.default,
  };
}

// ─── Types ────────────────────────────────────────────────────────────
export interface ExecDashboardData {
  // Summary stats
  summary?: {
    totalEngagements: number;
    activeEngagements: number;
    completedEngagements: number;
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    totalScans: number;
    totalAssets: number;
    totalThreatGroups: number;
    avgRiskScore: number;
  };
  // MITRE coverage
  mitreCoverage?: {
    totalTechniques: number;
    coveredTechniques: number;
    coveragePercent: number;
    tacticBreakdown: Array<{ tactic: string; covered: number; total: number }>;
  };
  // C2 readiness
  c2Readiness?: {
    frameworks: Array<{
      id: string;
      name: string;
      status: string;
      techniques: number;
      postExploitCapabilities: number;
    }>;
    totalDeployed: number;
    totalLocal: number;
  };
  // Pipeline status
  pipelineStatus?: {
    schedulerEnabled: boolean;
    cronExpression: string;
    totalRuns: number;
    totalProfilesGenerated: number;
    totalProfilesPushed: number;
    lastRun?: {
      runId: string;
      status: string;
      startedAt: number;
      completedAt: number | null;
      actorsScanned: number;
      profilesGenerated: number;
      profilesPushed: number;
    } | null;
  };
  // Threat landscape
  threatLandscape?: {
    topActors: Array<{
      name: string;
      techniques: number;
      severity: string;
      lastSeen: string;
    }>;
    totalActors: number;
    actorsWithProfiles: number;
  };
}

// ─── Color Palette ────────────────────────────────────────────────────
const COLORS = {
  headerBg: [15, 23, 42] as [number, number, number],      // slate-900
  headerText: [255, 255, 255] as [number, number, number],
  accentBlue: [59, 130, 246] as [number, number, number],   // blue-500
  accentGreen: [34, 197, 94] as [number, number, number],   // green-500
  accentAmber: [245, 158, 11] as [number, number, number],  // amber-500
  accentRed: [239, 68, 68] as [number, number, number],     // red-500
  textPrimary: [15, 23, 42] as [number, number, number],    // slate-900
  textSecondary: [100, 116, 139] as [number, number, number], // slate-500
  tableBg: [30, 41, 59] as [number, number, number],        // slate-800
  altRow: [241, 245, 249] as [number, number, number],       // slate-100
  divider: [203, 213, 225] as [number, number, number],      // slate-300
  kpiBg: [248, 250, 252] as [number, number, number],        // slate-50
};

// ─── Helper: Draw KPI Card ───────────────────────────────────────────
function drawKpiCard(
  doc: any,
  x: number,
  y: number,
  width: number,
  height: number,
  label: string,
  value: string | number,
  color: [number, number, number],
) {
  // Card background
  doc.setFillColor(...COLORS.kpiBg);
  doc.roundedRect(x, y, width, height, 2, 2, "F");
  // Left accent bar
  doc.setFillColor(...color);
  doc.rect(x, y, 2, height, "F");
  // Value
  doc.setTextColor(...COLORS.textPrimary);
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text(String(value), x + 8, y + height / 2 - 1);
  // Label
  doc.setTextColor(...COLORS.textSecondary);
  doc.setFontSize(7);
  doc.setFont("helvetica", "normal");
  doc.text(label, x + 8, y + height / 2 + 5);
}

// ─── Helper: Section Header ──────────────────────────────────────────
function drawSectionHeader(doc: any, text: string, yPos: number, pageWidth: number): number {
  doc.setFillColor(...COLORS.accentBlue);
  doc.rect(14, yPos, pageWidth - 28, 0.5, "F");
  doc.setTextColor(...COLORS.textPrimary);
  doc.setFontSize(11);
  doc.setFont("helvetica", "bold");
  doc.text(text, 14, yPos + 6);
  return yPos + 10;
}

// ─── Main Export Function ─────────────────────────────────────────────
export async function exportExecutiveDashboardPdf(
  data: ExecDashboardData,
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({
    orientation: "landscape",
    unit: "mm",
    format: "a4",
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const now = new Date();
  const dateStr = now.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
  const timeStr = now.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  });

  // ─── Page Footer Helper ─────────────────────────────────────────────
  function addFooter() {
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(7);
      doc.setTextColor(...COLORS.textSecondary);
      doc.text(
        `Page ${i} of ${pageCount}`,
        pageWidth - 30,
        pageHeight - 6,
      );
      doc.text(
        "CONFIDENTIAL — AC3 Platform | AceofCloud",
        14,
        pageHeight - 6,
      );
      doc.setFillColor(...COLORS.divider);
      doc.rect(14, pageHeight - 10, pageWidth - 28, 0.3, "F");
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // PAGE 1: Executive Summary
  // ═══════════════════════════════════════════════════════════════════

  // Header banner
  doc.setFillColor(...COLORS.headerBg);
  doc.rect(0, 0, pageWidth, 32, "F");
  doc.setTextColor(...COLORS.headerText);
  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text("Executive Security Dashboard", 14, 14);
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text("AC3 — Offensive Security Operations Platform", 14, 21);
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text(`Report Generated: ${dateStr} at ${timeStr}`, 14, 28);
  doc.text("Author: Harrison Cook — AceofCloud", pageWidth - 70, 28);

  let yPos = 38;

  // ─── KPI Cards Row ─────────────────────────────────────────────────
  const s = data.summary;
  if (s) {
    const cardWidth = (pageWidth - 28 - 15) / 4; // 4 cards with gaps
    const cardHeight = 18;

    drawKpiCard(doc, 14, yPos, cardWidth, cardHeight,
      "Active Engagements", s.activeEngagements, COLORS.accentBlue);
    drawKpiCard(doc, 14 + cardWidth + 5, yPos, cardWidth, cardHeight,
      "Total Findings", s.totalFindings, COLORS.accentAmber);
    drawKpiCard(doc, 14 + (cardWidth + 5) * 2, yPos, cardWidth, cardHeight,
      "Critical Findings", s.criticalFindings, COLORS.accentRed);
    drawKpiCard(doc, 14 + (cardWidth + 5) * 3, yPos, cardWidth, cardHeight,
      "Avg Risk Score", `${s.avgRiskScore}/100`, COLORS.accentGreen);

    yPos += cardHeight + 6;

    drawKpiCard(doc, 14, yPos, cardWidth, cardHeight,
      "Total Engagements", s.totalEngagements, COLORS.accentBlue);
    drawKpiCard(doc, 14 + cardWidth + 5, yPos, cardWidth, cardHeight,
      "Scans Completed", s.totalScans, COLORS.accentGreen);
    drawKpiCard(doc, 14 + (cardWidth + 5) * 2, yPos, cardWidth, cardHeight,
      "Assets Discovered", s.totalAssets, COLORS.accentBlue);
    drawKpiCard(doc, 14 + (cardWidth + 5) * 3, yPos, cardWidth, cardHeight,
      "Threat Groups Tracked", s.totalThreatGroups, COLORS.accentRed);

    yPos += cardHeight + 8;
  }

  // ─── Findings Breakdown Table ──────────────────────────────────────
  if (s) {
    yPos = drawSectionHeader(doc, "Findings Severity Breakdown", yPos, pageWidth);

    autoTable(doc, {
      startY: yPos,
      head: [["Severity", "Count", "% of Total", "Status"]],
      body: [
        ["Critical", s.criticalFindings, s.totalFindings > 0 ? `${((s.criticalFindings / s.totalFindings) * 100).toFixed(1)}%` : "0%", s.criticalFindings > 0 ? "ACTION REQUIRED" : "Clear"],
        ["High", s.highFindings, s.totalFindings > 0 ? `${((s.highFindings / s.totalFindings) * 100).toFixed(1)}%` : "0%", s.highFindings > 5 ? "Elevated" : "Acceptable"],
        ["Medium", s.mediumFindings, s.totalFindings > 0 ? `${((s.mediumFindings / s.totalFindings) * 100).toFixed(1)}%` : "0%", "Monitor"],
        ["Low", s.lowFindings, s.totalFindings > 0 ? `${((s.lowFindings / s.totalFindings) * 100).toFixed(1)}%` : "0%", "Informational"],
      ],
      theme: "grid",
      headStyles: {
        fillColor: COLORS.tableBg,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: "bold",
        cellPadding: 2.5,
      },
      bodyStyles: {
        fontSize: 8,
        cellPadding: 2,
        textColor: COLORS.textPrimary,
      },
      alternateRowStyles: { fillColor: COLORS.altRow },
      columnStyles: {
        0: { fontStyle: "bold", cellWidth: 40 },
        1: { halign: "center", cellWidth: 30 },
        2: { halign: "center", cellWidth: 30 },
        3: { cellWidth: 40 },
      },
      margin: { left: 14, right: 14 },
    });
    yPos = (doc as any).lastAutoTable.finalY + 8;
  }

  // ═══════════════════════════════════════════════════════════════════
  // PAGE 2: MITRE ATT&CK Coverage
  // ═══════════════════════════════════════════════════════════════════
  doc.addPage();
  yPos = 14;

  // Section header
  doc.setFillColor(...COLORS.headerBg);
  doc.rect(0, 0, pageWidth, 20, "F");
  doc.setTextColor(...COLORS.headerText);
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text("MITRE ATT&CK Coverage Analysis", 14, 13);

  yPos = 26;

  if (data.mitreCoverage) {
    const mc = data.mitreCoverage;

    // Coverage summary cards
    const cardW = (pageWidth - 28 - 10) / 3;
    drawKpiCard(doc, 14, yPos, cardW, 18,
      "Total Techniques", mc.totalTechniques, COLORS.accentBlue);
    drawKpiCard(doc, 14 + cardW + 5, yPos, cardW, 18,
      "Covered Techniques", mc.coveredTechniques, COLORS.accentGreen);
    drawKpiCard(doc, 14 + (cardW + 5) * 2, yPos, cardW, 18,
      "Coverage Rate", `${mc.coveragePercent.toFixed(1)}%`, 
      mc.coveragePercent >= 70 ? COLORS.accentGreen : mc.coveragePercent >= 40 ? COLORS.accentAmber : COLORS.accentRed);

    yPos += 26;

    // Tactic breakdown table
    if (mc.tacticBreakdown && mc.tacticBreakdown.length > 0) {
      yPos = drawSectionHeader(doc, "Coverage by Tactic", yPos, pageWidth);

      autoTable(doc, {
        startY: yPos,
        head: [["Tactic", "Covered", "Total", "Coverage %", "Assessment"]],
        body: mc.tacticBreakdown.map((t) => {
          const pct = t.total > 0 ? ((t.covered / t.total) * 100) : 0;
          const assessment = pct >= 80 ? "Strong" : pct >= 50 ? "Moderate" : pct >= 25 ? "Weak" : "Gap";
          return [
            t.tactic.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
            t.covered,
            t.total,
            `${pct.toFixed(1)}%`,
            assessment,
          ];
        }),
        theme: "grid",
        headStyles: {
          fillColor: COLORS.tableBg,
          textColor: [255, 255, 255],
          fontSize: 8,
          fontStyle: "bold",
          cellPadding: 2.5,
        },
        bodyStyles: {
          fontSize: 8,
          cellPadding: 2,
          textColor: COLORS.textPrimary,
        },
        alternateRowStyles: { fillColor: COLORS.altRow },
        columnStyles: {
          0: { fontStyle: "bold", cellWidth: 55 },
          1: { halign: "center", cellWidth: 25 },
          2: { halign: "center", cellWidth: 25 },
          3: { halign: "center", cellWidth: 30 },
          4: { cellWidth: 35 },
        },
        margin: { left: 14, right: 14 },
      });
      yPos = (doc as any).lastAutoTable.finalY + 8;
    }
  } else {
    doc.setTextColor(...COLORS.textSecondary);
    doc.setFontSize(10);
    doc.text("MITRE ATT&CK coverage data not available.", 14, yPos);
    yPos += 10;
  }

  // ═══════════════════════════════════════════════════════════════════
  // PAGE 3: C2 Operational Readiness & Automation Pipeline
  // ═══════════════════════════════════════════════════════════════════
  doc.addPage();
  yPos = 14;

  doc.setFillColor(...COLORS.headerBg);
  doc.rect(0, 0, pageWidth, 20, "F");
  doc.setTextColor(...COLORS.headerText);
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text("C2 Operational Readiness & Automation Pipeline", 14, 13);

  yPos = 26;

  // C2 Framework Readiness
  if (data.c2Readiness) {
    yPos = drawSectionHeader(doc, "C2 Framework Readiness", yPos, pageWidth);

    autoTable(doc, {
      startY: yPos,
      head: [["Framework", "Status", "Techniques", "Post-Exploit Capabilities", "Assessment"]],
      body: data.c2Readiness.frameworks.map((fw) => [
        fw.name,
        fw.status,
        fw.techniques,
        fw.postExploitCapabilities,
        fw.techniques > 30 ? "Full Capability" : fw.techniques > 15 ? "Operational" : "Limited",
      ]),
      theme: "grid",
      headStyles: {
        fillColor: COLORS.tableBg,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: "bold",
        cellPadding: 2.5,
      },
      bodyStyles: {
        fontSize: 8,
        cellPadding: 2,
        textColor: COLORS.textPrimary,
      },
      alternateRowStyles: { fillColor: COLORS.altRow },
      margin: { left: 14, right: 14 },
    });
    yPos = (doc as any).lastAutoTable.finalY + 8;

    // Deployment summary
    const deployCardW = (pageWidth - 28 - 5) / 2;
    drawKpiCard(doc, 14, yPos, deployCardW, 16,
      "Profiles Deployed to Caldera", data.c2Readiness.totalDeployed, COLORS.accentGreen);
    drawKpiCard(doc, 14 + deployCardW + 5, yPos, deployCardW, 16,
      "Profiles Local Only", data.c2Readiness.totalLocal, COLORS.accentAmber);
    yPos += 24;
  }

  // Automation Pipeline Status
  if (data.pipelineStatus) {
    yPos = drawSectionHeader(doc, "Automation Pipeline Status", yPos, pageWidth);

    const ps = data.pipelineStatus;
    const pipelineCards = [
      { label: "Scheduler", value: ps.schedulerEnabled ? "Active" : "Disabled", color: ps.schedulerEnabled ? COLORS.accentGreen : COLORS.accentRed },
      { label: "Schedule", value: ps.cronExpression, color: COLORS.accentBlue },
      { label: "Total Runs", value: ps.totalRuns, color: COLORS.accentBlue },
      { label: "Profiles Generated", value: ps.totalProfilesGenerated, color: COLORS.accentGreen },
    ];

    const pCardW = (pageWidth - 28 - 15) / 4;
    pipelineCards.forEach((card, i) => {
      drawKpiCard(doc, 14 + i * (pCardW + 5), yPos, pCardW, 16,
        card.label, card.value, card.color);
    });
    yPos += 24;

    // Last run details
    if (ps.lastRun) {
      autoTable(doc, {
        startY: yPos,
        head: [["Run ID", "Status", "Trigger", "Actors Scanned", "Generated", "Pushed", "Duration"]],
        body: [[
          ps.lastRun.runId,
          ps.lastRun.status.toUpperCase(),
          "Scheduled",
          ps.lastRun.actorsScanned,
          ps.lastRun.profilesGenerated,
          ps.lastRun.profilesPushed,
          ps.lastRun.completedAt
            ? `${((ps.lastRun.completedAt - ps.lastRun.startedAt) / 1000).toFixed(1)}s`
            : "In Progress",
        ]],
        theme: "grid",
        headStyles: {
          fillColor: COLORS.tableBg,
          textColor: [255, 255, 255],
          fontSize: 7,
          fontStyle: "bold",
          cellPadding: 2,
        },
        bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: COLORS.textPrimary },
        margin: { left: 14, right: 14 },
      });
      yPos = (doc as any).lastAutoTable.finalY + 8;
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // PAGE 4: Threat Landscape
  // ═══════════════════════════════════════════════════════════════════
  if (data.threatLandscape && data.threatLandscape.topActors.length > 0) {
    doc.addPage();
    yPos = 14;

    doc.setFillColor(...COLORS.headerBg);
    doc.rect(0, 0, pageWidth, 20, "F");
    doc.setTextColor(...COLORS.headerText);
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Threat Landscape Overview", 14, 13);

    yPos = 26;

    const tl = data.threatLandscape;
    const tlCardW = (pageWidth - 28 - 5) / 2;
    drawKpiCard(doc, 14, yPos, tlCardW, 16,
      "Total Threat Actors Tracked", tl.totalActors, COLORS.accentRed);
    drawKpiCard(doc, 14 + tlCardW + 5, yPos, tlCardW, 16,
      "Actors with Adversary Profiles", tl.actorsWithProfiles, COLORS.accentGreen);
    yPos += 24;

    yPos = drawSectionHeader(doc, "Top Threat Actors by Technique Coverage", yPos, pageWidth);

    autoTable(doc, {
      startY: yPos,
      head: [["Threat Actor", "Techniques", "Severity", "Last Seen"]],
      body: tl.topActors.map((a) => [
        a.name,
        a.techniques,
        a.severity,
        a.lastSeen,
      ]),
      theme: "grid",
      headStyles: {
        fillColor: COLORS.tableBg,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: "bold",
        cellPadding: 2.5,
      },
      bodyStyles: {
        fontSize: 8,
        cellPadding: 2,
        textColor: COLORS.textPrimary,
      },
      alternateRowStyles: { fillColor: COLORS.altRow },
      columnStyles: {
        0: { fontStyle: "bold", cellWidth: 60 },
        1: { halign: "center", cellWidth: 30 },
        2: { cellWidth: 30 },
        3: { cellWidth: 40 },
      },
      margin: { left: 14, right: 14 },
    });
  }

  // ─── Add footers to all pages ──────────────────────────────────────
  addFooter();

  // ─── Save ──────────────────────────────────────────────────────────
  const filename = `AC3_Executive_Dashboard_${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
}
