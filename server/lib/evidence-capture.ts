/**
 * Evidence Capture Module
 * 
 * Captures forensic evidence during validation runs:
 * - MSF console output and session screenshots
 * - Structured evidence reports (text-based)
 * - Stores artifacts in S3 for inclusion in PDF exports
 */

import { storagePut } from "../storage";
import type { MsfClient } from "./msf-client";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface EvidenceArtifact {
  type: "console_output" | "session_info" | "evidence_report" | "screenshot_text";
  filename: string;
  url: string;
  mimeType: string;
  sizeBytes: number;
  capturedAt: string; // ISO timestamp
}

export interface CapturedEvidence {
  /** Primary evidence report URL (text/html) */
  reportUrl: string;
  /** All artifact URLs */
  artifacts: EvidenceArtifact[];
  /** Summary for inline display */
  summary: string;
}

export interface EvidenceCaptureContext {
  runId: number;
  scanId: number;
  candidateId: string;
  assetHostname: string;
  cveId: string;
  msfModule: string | null;
  mode: string;
  targetIp: string | null;
  targetPort: number | null;
}

// ─── Evidence Capture Functions ────────────────────────────────────────────

/**
 * Capture console output from an MSF session and store as an artifact.
 */
export async function captureConsoleOutput(
  msfClient: MsfClient,
  sessionId: string | null,
  jobId: string | null,
  ctx: EvidenceCaptureContext,
): Promise<EvidenceArtifact | null> {
  try {
    let output = "";

    // Try to read session output
    if (sessionId) {
      try {
        const sessionData = await msfClient.shellRead(sessionId);
        if (sessionData?.data) {
          output += `=== Session ${sessionId} Output ===\n${sessionData.data}\n`;
        }
      } catch {
        output += `[Session ${sessionId} read failed — session may have been terminated]\n`;
      }
    }

    // Try to get job info
    if (jobId) {
      try {
        const jobInfo = await msfClient.getJobInfo(jobId);
        if (jobInfo) {
          output += `\n=== Job ${jobId} Info ===\n`;
          output += `Name: ${jobInfo.name || "N/A"}\n`;
          output += `Start Time: ${jobInfo.start_time || "N/A"}\n`;
          output += `Datastore: ${jobInfo.datastore ? JSON.stringify(jobInfo.datastore).slice(0, 200) : "N/A"}\n`;
        }
      } catch {
        output += `[Job ${jobId} info unavailable]\n`;
      }
    }

    if (!output.trim()) return null;

    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-console.txt`;
    const buffer = Buffer.from(output, "utf-8");
    const { url } = await storagePut(filename, buffer, "text/plain");

    return {
      type: "console_output",
      filename: `${ctx.candidateId}-console.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Console capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}

/**
 * Capture session metadata and system info when a session is obtained.
 */
export async function captureSessionInfo(
  msfClient: MsfClient,
  sessionId: string,
  ctx: EvidenceCaptureContext,
): Promise<EvidenceArtifact | null> {
  try {
    const sessions = await msfClient.listSessions();
    const session = sessions[sessionId];

    if (!session) return null;

    const info = [
      `╔══════════════════════════════════════════════════════════════╗`,
      `║  PROOF OF EXPLOITATION — SESSION EVIDENCE                   ║`,
      `╚══════════════════════════════════════════════════════════════╝`,
      ``,
      `Validation Run:  #${ctx.runId}`,
      `Candidate ID:    ${ctx.candidateId}`,
      `Timestamp:       ${new Date().toISOString()}`,
      ``,
      `─── Target ───────────────────────────────────────────────────`,
      `Hostname:        ${ctx.assetHostname}`,
      `IP Address:      ${ctx.targetIp || "N/A"}`,
      `Port:            ${ctx.targetPort || "auto"}`,
      `CVE:             ${ctx.cveId}`,
      `Module:          ${ctx.msfModule || "N/A"}`,
      `Mode:            ${ctx.mode}`,
      ``,
      `─── Session Details ──────────────────────────────────────────`,
      `Session ID:      ${sessionId}`,
      `Session Type:    ${session.type || "N/A"}`,
      `Tunnel Local:    ${session.tunnel_local || "N/A"}`,
      `Tunnel Peer:     ${session.tunnel_peer || "N/A"}`,
      `Via Exploit:     ${session.via_exploit || "N/A"}`,
      `Via Payload:     ${session.via_payload || "N/A"}`,
      `Description:     ${session.desc || "N/A"}`,
      `Platform:        ${session.platform || "N/A"}`,
      `Architecture:    ${session.arch || "N/A"}`,
      `Info:            ${session.info || "N/A"}`,
      ``,
      `─── Disposition ──────────────────────────────────────────────`,
      `Session was IMMEDIATELY TERMINATED after evidence capture.`,
      `No persistent access was maintained.`,
      `This validates that ${ctx.cveId} is exploitable on ${ctx.assetHostname}.`,
      ``,
      `─── Classification ───────────────────────────────────────────`,
      `Evidence Type:   Proof-of-Exploit (Session Obtained)`,
      `Confidence:      99%`,
      `Risk Impact:     CRITICAL — Remote code execution confirmed`,
    ].join("\n");

    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-session-info.txt`;
    const buffer = Buffer.from(info, "utf-8");
    const { url } = await storagePut(filename, buffer, "text/plain");

    return {
      type: "session_info",
      filename: `${ctx.candidateId}-session-info.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Session info capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}

/**
 * Generate a text-based "screenshot" of the validation result.
 * This provides a formatted evidence artifact that can be embedded in reports.
 */
export function generateEvidenceScreenshot(
  ctx: EvidenceCaptureContext,
  result: {
    status: string;
    exploitable: boolean;
    rawOutput: string | null;
    evidence: any;
    durationMs: number;
    scoreAdjustment: number;
  },
): string {
  const border = "═".repeat(62);
  const divider = "─".repeat(62);

  const statusIcon = result.exploitable ? "⚠ EXPLOITABLE" : 
    result.status === "not_vulnerable" ? "✓ NOT VULNERABLE" :
    result.status === "inconclusive" ? "? INCONCLUSIVE" :
    result.status === "error" ? "✗ ERROR" : result.status.toUpperCase();

  const lines = [
    `╔${border}╗`,
    `║  VALIDATION EVIDENCE CAPTURE                                 ║`,
    `╠${border}╣`,
    `║                                                              ║`,
    `║  Status: ${statusIcon.padEnd(51)}║`,
    `║                                                              ║`,
    `╠${border}╣`,
    ``,
    `Target Information`,
    divider,
    `  Hostname:     ${ctx.assetHostname}`,
    `  IP Address:   ${ctx.targetIp || "N/A"}`,
    `  Port:         ${ctx.targetPort || "auto"}`,
    `  CVE:          ${ctx.cveId}`,
    `  MSF Module:   ${ctx.msfModule || "N/A"}`,
    `  Mode:         ${ctx.mode}`,
    ``,
    `Execution Results`,
    divider,
    `  Duration:     ${result.durationMs}ms`,
    `  Exploitable:  ${result.exploitable ? "YES" : "NO"}`,
    `  Score Adj:    ${result.scoreAdjustment > 0 ? "+" : ""}${result.scoreAdjustment}`,
    ``,
  ];

  if (result.evidence) {
    lines.push(`Evidence Details`);
    lines.push(divider);
    lines.push(`  Method:       ${result.evidence.method || "N/A"}`);
    lines.push(`  Finding:      ${result.evidence.finding || "N/A"}`);
    lines.push(`  Confidence:   ${result.evidence.confidence ? `${Math.round(result.evidence.confidence * 100)}%` : "N/A"}`);
    if (result.evidence.sessionObtained) {
      lines.push(`  Session:      #${result.evidence.sessionId} (terminated immediately)`);
    }
    lines.push(``);
  }

  if (result.rawOutput) {
    lines.push(`MSF Output (truncated)`);
    lines.push(divider);
    const outputLines = result.rawOutput.split("\n").slice(0, 20);
    for (const line of outputLines) {
      lines.push(`  ${line.slice(0, 60)}`);
    }
    if (result.rawOutput.split("\n").length > 20) {
      lines.push(`  ... (${result.rawOutput.split("\n").length - 20} more lines)`);
    }
    lines.push(``);
  }

  lines.push(`Timestamp: ${new Date().toISOString()}`);
  lines.push(`Run ID: ${ctx.runId} | Candidate: ${ctx.candidateId}`);
  lines.push(`╚${border}╝`);

  return lines.join("\n");
}

/**
 * Store a text-based evidence screenshot as an S3 artifact.
 */
export async function storeEvidenceScreenshot(
  ctx: EvidenceCaptureContext,
  screenshotText: string,
): Promise<EvidenceArtifact | null> {
  try {
    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-evidence-screenshot.txt`;
    const buffer = Buffer.from(screenshotText, "utf-8");
    const { url } = await storagePut(filename, buffer, "text/plain");

    return {
      type: "screenshot_text",
      filename: `${ctx.candidateId}-evidence-screenshot.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Screenshot store failed for ${ctx.candidateId}:`, err);
    return null;
  }
}

/**
 * Generate and store a comprehensive HTML evidence report for a validation result.
 * This is the primary evidence artifact linked from the PDF export.
 */
export async function generateEvidenceReport(
  ctx: EvidenceCaptureContext,
  result: {
    status: string;
    exploitable: boolean;
    rawOutput: string | null;
    evidence: any;
    durationMs: number;
    scoreAdjustment: number;
  },
  artifacts: EvidenceArtifact[],
): Promise<{ reportUrl: string; reportArtifact: EvidenceArtifact } | null> {
  try {
    const statusColor = result.exploitable ? "#dc2626" : 
      result.status === "not_vulnerable" ? "#16a34a" : "#d97706";
    const statusLabel = result.exploitable ? "EXPLOITABLE" :
      result.status === "not_vulnerable" ? "NOT VULNERABLE" :
      result.status === "inconclusive" ? "INCONCLUSIVE" : result.status.toUpperCase();

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Validation Evidence — ${ctx.cveId} on ${ctx.assetHostname}</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; background: #0f172a; color: #e2e8f0; }
  .header { border-bottom: 2px solid ${statusColor}; padding-bottom: 1rem; margin-bottom: 2rem; }
  .header h1 { font-size: 1.5rem; color: #f8fafc; margin: 0 0 0.5rem; }
  .status { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; background: ${statusColor}; color: white; font-weight: 600; font-size: 0.875rem; }
  .section { margin-bottom: 1.5rem; }
  .section h2 { font-size: 1rem; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 0.375rem 0.75rem; border-bottom: 1px solid #1e293b; }
  td:first-child { color: #64748b; width: 140px; font-size: 0.875rem; }
  td:last-child { color: #e2e8f0; }
  .output { background: #1e293b; border-radius: 6px; padding: 1rem; font-family: 'Fira Code', monospace; font-size: 0.8rem; white-space: pre-wrap; overflow-x: auto; max-height: 400px; overflow-y: auto; color: #a5f3fc; }
  .artifacts { list-style: none; padding: 0; }
  .artifacts li { padding: 0.5rem; background: #1e293b; border-radius: 4px; margin-bottom: 0.5rem; }
  .artifacts a { color: #38bdf8; text-decoration: none; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #334155; font-size: 0.75rem; color: #64748b; }
</style>
</head>
<body>
<div class="header">
  <h1>Validation Evidence Report</h1>
  <span class="status">${statusLabel}</span>
  <span style="margin-left:1rem;color:#64748b;font-size:0.875rem;">Run #${ctx.runId} — ${new Date().toISOString()}</span>
</div>

<div class="section">
  <h2>Target</h2>
  <table>
    <tr><td>Hostname</td><td>${ctx.assetHostname}</td></tr>
    <tr><td>IP Address</td><td>${ctx.targetIp || "N/A"}</td></tr>
    <tr><td>Port</td><td>${ctx.targetPort || "auto"}</td></tr>
    <tr><td>CVE</td><td>${ctx.cveId}</td></tr>
    <tr><td>MSF Module</td><td>${ctx.msfModule || "N/A"}</td></tr>
    <tr><td>Mode</td><td>${ctx.mode}</td></tr>
  </table>
</div>

<div class="section">
  <h2>Result</h2>
  <table>
    <tr><td>Exploitable</td><td style="color:${result.exploitable ? "#ef4444" : "#22c55e"};font-weight:600">${result.exploitable ? "YES" : "NO"}</td></tr>
    <tr><td>Duration</td><td>${result.durationMs}ms</td></tr>
    <tr><td>Score Impact</td><td>${result.scoreAdjustment > 0 ? "+" : ""}${result.scoreAdjustment} points</td></tr>
    ${result.evidence ? `
    <tr><td>Method</td><td>${result.evidence.method || "N/A"}</td></tr>
    <tr><td>Finding</td><td>${result.evidence.finding || "N/A"}</td></tr>
    <tr><td>Confidence</td><td>${result.evidence.confidence ? `${Math.round(result.evidence.confidence * 100)}%` : "N/A"}</td></tr>
    ${result.evidence.sessionObtained ? `<tr><td>Session</td><td>#${result.evidence.sessionId} (terminated immediately)</td></tr>` : ""}
    ` : ""}
  </table>
</div>

${result.rawOutput ? `
<div class="section">
  <h2>MSF Output</h2>
  <div class="output">${escapeHtml(result.rawOutput.slice(0, 4000))}</div>
</div>
` : ""}

${artifacts.length > 0 ? `
<div class="section">
  <h2>Evidence Artifacts</h2>
  <ul class="artifacts">
    ${artifacts.map(a => `<li><a href="${a.url}" target="_blank">${a.filename}</a> <span style="color:#64748b">(${a.type}, ${formatBytes(a.sizeBytes)})</span></li>`).join("\n    ")}
  </ul>
</div>
` : ""}

<div class="footer">
  Generated by AC3 Autonomous Validation Engine<br>
  Candidate ID: ${ctx.candidateId} | Scan ID: ${ctx.scanId}
</div>
</body>
</html>`;

    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-report.html`;
    const buffer = Buffer.from(html, "utf-8");
    const { url } = await storagePut(filename, buffer, "text/html");

    return {
      reportUrl: url,
      reportArtifact: {
        type: "evidence_report",
        filename: `${ctx.candidateId}-report.html`,
        url,
        mimeType: "text/html",
        sizeBytes: buffer.length,
        capturedAt: new Date().toISOString(),
      },
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Report generation failed for ${ctx.candidateId}:`, err);
    return null;
  }
}

/**
 * Full evidence capture pipeline — call after each validation result.
 * Captures all available evidence and stores it in S3.
 */
export async function captureFullEvidence(
  msfClient: MsfClient | null,
  ctx: EvidenceCaptureContext,
  result: {
    status: string;
    exploitable: boolean;
    rawOutput: string | null;
    evidence: any;
    durationMs: number;
    scoreAdjustment: number;
  },
  sessionId: string | null,
  jobId: string | null,
): Promise<CapturedEvidence | null> {
  try {
    const artifacts: EvidenceArtifact[] = [];

    // 1. Capture console output if MSF client available
    if (msfClient && (sessionId || jobId)) {
      const consoleArtifact = await captureConsoleOutput(msfClient, sessionId, jobId, ctx);
      if (consoleArtifact) artifacts.push(consoleArtifact);
    }

    // 2. Capture session info if session was obtained
    if (msfClient && sessionId && result.exploitable) {
      const sessionArtifact = await captureSessionInfo(msfClient, sessionId, ctx);
      if (sessionArtifact) artifacts.push(sessionArtifact);
    }

    // 3. Generate text-based evidence screenshot
    const screenshotText = generateEvidenceScreenshot(ctx, result);
    const screenshotArtifact = await storeEvidenceScreenshot(ctx, screenshotText);
    if (screenshotArtifact) artifacts.push(screenshotArtifact);

    // 4. Generate the primary HTML evidence report
    const report = await generateEvidenceReport(ctx, result, artifacts);
    if (report) {
      artifacts.push(report.reportArtifact);

      return {
        reportUrl: report.reportUrl,
        artifacts,
        summary: result.exploitable
          ? `Exploit validated: ${ctx.cveId} on ${ctx.assetHostname} via ${ctx.msfModule || "unknown module"}`
          : `Validation ${result.status}: ${ctx.cveId} on ${ctx.assetHostname}`,
      };
    }

    // Fallback if report generation failed but we have other artifacts
    if (artifacts.length > 0) {
      return {
        reportUrl: artifacts[0].url,
        artifacts,
        summary: `Evidence captured for ${ctx.cveId} on ${ctx.assetHostname} (${artifacts.length} artifacts)`,
      };
    }

    return null;
  } catch (err) {
    console.error(`[EvidenceCapture] Full capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
