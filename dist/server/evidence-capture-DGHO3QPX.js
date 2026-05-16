import {
  doStoragePut,
  init_do_storage
} from "./chunk-P3AH34HJ.js";
import "./chunk-KDOLKO2A.js";
import "./chunk-KFQGP6VL.js";

// server/lib/evidence-capture.ts
init_do_storage();
async function captureConsoleOutput(msfClient, sessionId, jobId, ctx) {
  try {
    let output = "";
    if (sessionId) {
      try {
        const sessionData = await msfClient.shellRead(sessionId);
        if (sessionData?.data) {
          output += `=== Session ${sessionId} Output ===
${sessionData.data}
`;
        }
      } catch {
        output += `[Session ${sessionId} read failed \u2014 session may have been terminated]
`;
      }
    }
    if (jobId) {
      try {
        const jobInfo = await msfClient.getJobInfo(jobId);
        if (jobInfo) {
          output += `
=== Job ${jobId} Info ===
`;
          output += `Name: ${jobInfo.name || "N/A"}
`;
          output += `Start Time: ${jobInfo.start_time || "N/A"}
`;
          output += `Datastore: ${jobInfo.datastore ? JSON.stringify(jobInfo.datastore).slice(0, 200) : "N/A"}
`;
        }
      } catch {
        output += `[Job ${jobId} info unavailable]
`;
      }
    }
    if (!output.trim()) return null;
    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-console.txt`;
    const buffer = Buffer.from(output, "utf-8");
    const { url } = await doStoragePut(filename, buffer, "text/plain");
    return {
      type: "console_output",
      filename: `${ctx.candidateId}-console.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Console capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}
async function captureSessionInfo(msfClient, sessionId, ctx) {
  try {
    const sessions = await msfClient.listSessions();
    const session = sessions[sessionId];
    if (!session) return null;
    const info = [
      `\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557`,
      `\u2551  PROOF OF EXPLOITATION \u2014 SESSION EVIDENCE                   \u2551`,
      `\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D`,
      ``,
      `Validation Run:  #${ctx.runId}`,
      `Candidate ID:    ${ctx.candidateId}`,
      `Timestamp:       ${(/* @__PURE__ */ new Date()).toISOString()}`,
      ``,
      `\u2500\u2500\u2500 Target \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`,
      `Hostname:        ${ctx.assetHostname}`,
      `IP Address:      ${ctx.targetIp || "N/A"}`,
      `Port:            ${ctx.targetPort || "auto"}`,
      `CVE:             ${ctx.cveId}`,
      `Module:          ${ctx.msfModule || "N/A"}`,
      `Mode:            ${ctx.mode}`,
      ``,
      `\u2500\u2500\u2500 Session Details \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`,
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
      `\u2500\u2500\u2500 Disposition \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`,
      `Session was IMMEDIATELY TERMINATED after evidence capture.`,
      `No persistent access was maintained.`,
      `This validates that ${ctx.cveId} is exploitable on ${ctx.assetHostname}.`,
      ``,
      `\u2500\u2500\u2500 Classification \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`,
      `Evidence Type:   Proof-of-Exploit (Session Obtained)`,
      `Confidence:      99%`,
      `Risk Impact:     CRITICAL \u2014 Remote code execution confirmed`
    ].join("\n");
    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-session-info.txt`;
    const buffer = Buffer.from(info, "utf-8");
    const { url } = await doStoragePut(filename, buffer, "text/plain");
    return {
      type: "session_info",
      filename: `${ctx.candidateId}-session-info.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Session info capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}
function generateEvidenceScreenshot(ctx, result) {
  const border = "\u2550".repeat(62);
  const divider = "\u2500".repeat(62);
  const statusIcon = result.exploitable ? "\u26A0 EXPLOITABLE" : result.status === "not_vulnerable" ? "\u2713 NOT VULNERABLE" : result.status === "inconclusive" ? "? INCONCLUSIVE" : result.status === "error" ? "\u2717 ERROR" : result.status.toUpperCase();
  const lines = [
    `\u2554${border}\u2557`,
    `\u2551  VALIDATION EVIDENCE CAPTURE                                 \u2551`,
    `\u2560${border}\u2563`,
    `\u2551                                                              \u2551`,
    `\u2551  Status: ${statusIcon.padEnd(51)}\u2551`,
    `\u2551                                                              \u2551`,
    `\u2560${border}\u2563`,
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
    ``
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
  lines.push(`Timestamp: ${(/* @__PURE__ */ new Date()).toISOString()}`);
  lines.push(`Run ID: ${ctx.runId} | Candidate: ${ctx.candidateId}`);
  lines.push(`\u255A${border}\u255D`);
  return lines.join("\n");
}
async function storeEvidenceScreenshot(ctx, screenshotText) {
  try {
    const filename = `evidence/${ctx.runId}/${ctx.candidateId}-evidence-screenshot.txt`;
    const buffer = Buffer.from(screenshotText, "utf-8");
    const { url } = await doStoragePut(filename, buffer, "text/plain");
    return {
      type: "screenshot_text",
      filename: `${ctx.candidateId}-evidence-screenshot.txt`,
      url,
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      capturedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Screenshot store failed for ${ctx.candidateId}:`, err);
    return null;
  }
}
async function generateEvidenceReport(ctx, result, artifacts) {
  try {
    const statusColor = result.exploitable ? "#dc2626" : result.status === "not_vulnerable" ? "#16a34a" : "#d97706";
    const statusLabel = result.exploitable ? "EXPLOITABLE" : result.status === "not_vulnerable" ? "NOT VULNERABLE" : result.status === "inconclusive" ? "INCONCLUSIVE" : result.status.toUpperCase();
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Validation Evidence \u2014 ${ctx.cveId} on ${ctx.assetHostname}</title>
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
  <span style="margin-left:1rem;color:#64748b;font-size:0.875rem;">Run #${ctx.runId} \u2014 ${(/* @__PURE__ */ new Date()).toISOString()}</span>
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
  <div class="output">${escapeHtml(result.rawOutput.slice(0, 4e3))}</div>
</div>
` : ""}

${artifacts.length > 0 ? `
<div class="section">
  <h2>Evidence Artifacts</h2>
  <ul class="artifacts">
    ${artifacts.map((a) => `<li><a href="${a.url}" target="_blank">${a.filename}</a> <span style="color:#64748b">(${a.type}, ${formatBytes(a.sizeBytes)})</span></li>`).join("\n    ")}
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
    const { url } = await doStoragePut(filename, buffer, "text/html");
    return {
      reportUrl: url,
      reportArtifact: {
        type: "evidence_report",
        filename: `${ctx.candidateId}-report.html`,
        url,
        mimeType: "text/html",
        sizeBytes: buffer.length,
        capturedAt: (/* @__PURE__ */ new Date()).toISOString()
      }
    };
  } catch (err) {
    console.error(`[EvidenceCapture] Report generation failed for ${ctx.candidateId}:`, err);
    return null;
  }
}
async function captureFullEvidence(msfClient, ctx, result, sessionId, jobId) {
  try {
    const artifacts = [];
    if (msfClient && (sessionId || jobId)) {
      const consoleArtifact = await captureConsoleOutput(msfClient, sessionId, jobId, ctx);
      if (consoleArtifact) artifacts.push(consoleArtifact);
    }
    if (msfClient && sessionId && result.exploitable) {
      const sessionArtifact = await captureSessionInfo(msfClient, sessionId, ctx);
      if (sessionArtifact) artifacts.push(sessionArtifact);
    }
    const screenshotText = generateEvidenceScreenshot(ctx, result);
    const screenshotArtifact = await storeEvidenceScreenshot(ctx, screenshotText);
    if (screenshotArtifact) artifacts.push(screenshotArtifact);
    const report = await generateEvidenceReport(ctx, result, artifacts);
    if (report) {
      artifacts.push(report.reportArtifact);
      return {
        reportUrl: report.reportUrl,
        artifacts,
        summary: result.exploitable ? `Exploit validated: ${ctx.cveId} on ${ctx.assetHostname} via ${ctx.msfModule || "unknown module"}` : `Validation ${result.status}: ${ctx.cveId} on ${ctx.assetHostname}`
      };
    }
    if (artifacts.length > 0) {
      return {
        reportUrl: artifacts[0].url,
        artifacts,
        summary: `Evidence captured for ${ctx.cveId} on ${ctx.assetHostname} (${artifacts.length} artifacts)`
      };
    }
    return null;
  } catch (err) {
    console.error(`[EvidenceCapture] Full capture failed for ${ctx.candidateId}:`, err);
    return null;
  }
}
function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
export {
  captureConsoleOutput,
  captureFullEvidence,
  captureSessionInfo,
  generateEvidenceReport,
  generateEvidenceScreenshot,
  storeEvidenceScreenshot
};
