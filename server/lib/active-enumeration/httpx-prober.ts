/**
 * Phase 5 Sub-module: httpx HTTP Prober (Phase A Step 3)
 *
 * HTTP probing on discovered web ports:
 * - Technology detection from response headers
 * - CDN/WAF detection
 * - TLS certificate analysis
 * - Port backfill for cloud-hosted targets
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";

/**
 * Run httpx probing on all web ports for an asset.
 * Enriches asset with technology stack, CDN/WAF info, and response headers.
 */
export async function runHttpxProbing(
  state: EngagementOpsState,
  asset: any,
  target: string,
  discoveredPorts: Array<{ port: number; protocol: string; service: string }>,
  helpers: EnumerationHelpers
): Promise<void> {
  const webPorts = discoveredPorts.filter(
    (p) =>
      ["http", "https", "http-proxy", "http-alt", "ssl"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000, 9443].includes(p.port)
  );

  // Also probe common web ports even if not detected as open
  const commonWebPorts = [80, 443, 8080, 8443];
  for (const wp of commonWebPorts) {
    if (!webPorts.find((p) => p.port === wp)) {
      webPorts.push({
        port: wp,
        protocol: "tcp",
        service: wp === 443 || wp === 8443 ? "https" : "http",
      });
    }
  }

  if (webPorts.length === 0) return;

  asset.type = "web_app";
  const assetPlan = state.scanPlan?.assetPlans.find(
    (ap) => ap.hostname === asset.hostname || ap.ip === target
  );
  const httpxFlags =
    assetPlan?.httpxFlags ||
    "-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent";

  // Build target URLs
  const httpxTargets = webPorts.map((p) => {
    const scheme =
      [443, 8443, 9443].includes(p.port) || p.service === "https" || p.service === "ssl"
        ? "https"
        : "http";
    return `${scheme}://${asset.hostname || target}:${p.port}`;
  });

  helpers.addLog({
    phase: "enumeration",
    type: "scan_start",
    title: `🌐 httpx: ${helpers.fmtTarget(asset, target)}`,
    detail: `Phase A Step 2 — HTTP probing ${webPorts.length} web ports\nTargets: ${httpxTargets.join(", ")}\nFlags: ${httpxFlags}`,
  });

  try {
    const httpxStart = Date.now();
    const httpxInput = httpxTargets.join("\\n");
    const httpxCmd = `echo -e '${httpxInput}' | httpx ${httpxFlags}`;
    helpers.addLog({
      phase: "enumeration",
      type: "tool_exec",
      title: `httpx ${helpers.fmtTarget(asset, target)}`,
      detail: httpxCmd,
    });

    const httpxResult = await helpers.executeRawCommand(httpxCmd, 120, {
      engagementId: state.engagementId,
    });
    const httpxDuration = Date.now() - httpxStart;

    // Parse httpx JSON output
    const httpxFindings: Array<{ severity: string; title: string }> = [];
    const techDetected: string[] = [];
    const cdnDetected: string[] = [];
    const responseHeaders: Record<string, string> = {};
    let webServer = "";
    let tlsInfo: any = "";
    const httpxLivePorts: Array<{ port: number; statusCode: number; title: string }> = [];

    if (httpxResult.stdout) {
      for (const line of httpxResult.stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);

          // Track per-port status codes
          if (obj.status_code && obj.port) {
            httpxLivePorts.push({ port: obj.port, statusCode: obj.status_code, title: obj.title || "" });
          } else if (obj.status_code && obj.url) {
            try {
              const parsedUrl = new URL(obj.url);
              const portNum = parsedUrl.port
                ? parseInt(parsedUrl.port)
                : parsedUrl.protocol === "https:" ? 443 : 80;
              httpxLivePorts.push({ port: portNum, statusCode: obj.status_code, title: obj.title || "" });
            } catch {}
          }

          // Technology detection
          if (obj.tech && Array.isArray(obj.tech)) {
            for (const tech of obj.tech) {
              if (!techDetected.includes(tech)) techDetected.push(tech);
              httpxFindings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
            }
          }

          // CDN/WAF detection
          if (obj.cdn_name) {
            if (!cdnDetected.includes(obj.cdn_name)) cdnDetected.push(obj.cdn_name);
            httpxFindings.push({ severity: "info", title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
          }
          if (obj.cdn === true) {
            httpxFindings.push({ severity: "info", title: `[httpx] CDN detected` });
          }

          // Web server
          if (obj.webserver) {
            webServer = obj.webserver;
            httpxFindings.push({ severity: "info", title: `[httpx] Web Server: ${obj.webserver}` });
          }

          // TLS info
          if (obj.tls) {
            const tls = obj.tls;
            tlsInfo = `${tls.version || ""} ${tls.cipher || ""}`.trim();
            if (tls.subject_cn) httpxFindings.push({ severity: "info", title: `[httpx] TLS CN: ${tls.subject_cn}` });
            if (tls.subject_org) httpxFindings.push({ severity: "info", title: `[httpx] TLS Org: ${tls.subject_org}` });
            if (tls.not_after) httpxFindings.push({ severity: "info", title: `[httpx] TLS Expires: ${tls.not_after}` });
          }

          // Status code + title
          if (obj.status_code) {
            httpxFindings.push({
              severity: "info",
              title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ""}`.trim(),
            });
          }

          // Content length
          if (obj.content_length !== undefined) {
            httpxFindings.push({ severity: "info", title: `[httpx] Content-Length: ${obj.content_length}` });
          }

          // Response header extraction
          const headers = obj.header || obj.response_header || {};
          parseResponseHeaders(headers, responseHeaders, techDetected, httpxFindings, webServer);
        } catch {
          /* not JSON line — skip */
        }
      }
    }

    // Enrich asset passiveRecon with httpx data
    if (asset.passiveRecon) {
      if (techDetected.length > 0) {
        asset.passiveRecon.technologies = Array.from(
          new Set([...(asset.passiveRecon.technologies || []), ...techDetected])
        );
      }
      if (cdnDetected.length > 0) {
        asset.passiveRecon.riskSignals = [
          ...(asset.passiveRecon.riskSignals || []),
          ...cdnDetected.map((c) => ({ severity: "low", type: "cdn_waf", rationale: `CDN/WAF detected: ${c}` })),
        ];
      }
      if (webServer) {
        asset.passiveRecon.technologies = Array.from(
          new Set([...(asset.passiveRecon.technologies || []), webServer])
        );
      }
      if (Object.keys(responseHeaders).length > 0) {
        (asset as any).httpxResponseHeaders = { ...(asset as any).httpxResponseHeaders, ...responseHeaders };
      }
      if (httpxLivePorts.length > 0) {
        (asset as any).httpxLivePorts = httpxLivePorts;
      }
    }

    // Store httpx result
    asset.toolResults.push({
      tool: "httpx",
      command: httpxCmd,
      exitCode: httpxResult.exitCode ?? 0,
      durationMs: httpxDuration,
      timedOut: httpxResult.timedOut || false,
      findingCount: httpxFindings.length,
      findings: httpxFindings,
      outputPreview: (httpxResult.stdout || "").slice(0, 1024),
      rawOutput: (httpxResult.stdout || "").slice(0, 50_000),
      executedAt: Date.now(),
      phase: "discovery",
      fingerprints: {
        webServer: webServer || undefined,
        technologies: techDetected.length > 0 ? techDetected : undefined,
        httpHeaders: Object.keys(responseHeaders).length > 0 ? responseHeaders : undefined,
        tlsInfo: tlsInfo
          ? { subjectCN: tlsInfo.subject_cn, issuerOrg: tlsInfo.issuer_org, notAfter: tlsInfo.not_after }
          : undefined,
        poweredBy: responseHeaders["x-powered-by"] || undefined,
        cookies: responseHeaders["set-cookie"] ? [responseHeaders["set-cookie"]] : undefined,
      },
    });

    helpers.addLog({
      phase: "enumeration",
      type: "scan_result",
      title: `httpx Complete: ${helpers.fmtTarget(asset, target)}`,
      detail: `${httpxFindings.length} findings in ${Math.round(httpxDuration / 1000)}s${techDetected.length > 0 ? `\nTech: ${techDetected.join(", ")}` : ""}${cdnDetected.length > 0 ? `\nCDN/WAF: ${cdnDetected.join(", ")}` : ""}${webServer ? `\nServer: ${webServer}` : ""}`,
      data: { tech: techDetected, cdn: cdnDetected, webServer, tls: tlsInfo },
    });

    // ── httpx Port Backfill ──
    if (asset.ports.length === 0 && webPorts.length > 0) {
      backfillPortsFromHttpx(state, asset, target, helpers);
    }
  } catch (e: any) {
    helpers.addLog({
      phase: "enumeration",
      type: "error",
      title: `httpx Failed: ${helpers.fmtTarget(asset, target)}`,
      detail: e.message,
    });
  }
}

// ─── Internal helpers ───────────────────────────────────────────────────────

function parseResponseHeaders(
  headers: any,
  responseHeaders: Record<string, string>,
  techDetected: string[],
  httpxFindings: Array<{ severity: string; title: string }>,
  webServer: string
): void {
  if (typeof headers === "object" && !Array.isArray(headers)) {
    for (const [key, val] of Object.entries(headers)) {
      const lk = key.toLowerCase();
      const headerVal = Array.isArray(val) ? val[0] : String(val);

      if (lk === "x-powered-by") {
        responseHeaders["x-powered-by"] = headerVal;
        httpxFindings.push({ severity: "info", title: `[httpx] X-Powered-By: ${headerVal}` });
        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
      }
      if (lk === "x-aspnet-version" || lk === "x-aspnetmvc-version") {
        responseHeaders[lk] = headerVal;
        httpxFindings.push({ severity: "info", title: `[httpx] ${key}: ${headerVal}` });
        if (!techDetected.includes(`ASP.NET ${headerVal}`)) techDetected.push(`ASP.NET ${headerVal}`);
      }
      if (lk === "x-generator") {
        responseHeaders["x-generator"] = headerVal;
        httpxFindings.push({ severity: "info", title: `[httpx] X-Generator: ${headerVal}` });
        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
      }
      if (lk === "set-cookie") {
        responseHeaders["set-cookie"] = headerVal;
        if (headerVal.includes("PHPSESSID") && !techDetected.includes("PHP")) techDetected.push("PHP");
        if (headerVal.includes("JSESSIONID") && !techDetected.includes("Java")) techDetected.push("Java");
        if (headerVal.includes("ASP.NET_SessionId") && !techDetected.includes("ASP.NET")) techDetected.push("ASP.NET");
        if (headerVal.includes("connect.sid") && !techDetected.includes("Node.js/Express")) techDetected.push("Node.js/Express");
        if (headerVal.includes("laravel_session") && !techDetected.includes("Laravel/PHP")) techDetected.push("Laravel/PHP");
        if (headerVal.includes("_rails") && !techDetected.includes("Ruby on Rails")) techDetected.push("Ruby on Rails");
        if (headerVal.includes("csrftoken") && !techDetected.includes("Django/Python")) techDetected.push("Django/Python");
        if (headerVal.includes("wp-settings") && !techDetected.includes("WordPress")) techDetected.push("WordPress");
      }
      if (lk === "server" && !webServer) {
        responseHeaders["server"] = headerVal;
      }
    }
  } else if (typeof headers === "string") {
    const headerLines = headers.split("\n");
    for (const hl of headerLines) {
      const colonIdx = hl.indexOf(":");
      if (colonIdx === -1) continue;
      const hName = hl.substring(0, colonIdx).trim().toLowerCase();
      const hVal = hl.substring(colonIdx + 1).trim();
      if (hName === "x-powered-by") {
        responseHeaders["x-powered-by"] = hVal;
        if (!techDetected.includes(hVal)) techDetected.push(hVal);
        httpxFindings.push({ severity: "info", title: `[httpx] X-Powered-By: ${hVal}` });
      }
      if (hName === "set-cookie") {
        responseHeaders["set-cookie"] = hVal;
        if (hVal.includes("PHPSESSID") && !techDetected.includes("PHP")) techDetected.push("PHP");
        if (hVal.includes("JSESSIONID") && !techDetected.includes("Java")) techDetected.push("Java");
        if (hVal.includes("ASP.NET_SessionId") && !techDetected.includes("ASP.NET")) techDetected.push("ASP.NET");
      }
    }
  }
}

function backfillPortsFromHttpx(
  state: EngagementOpsState,
  asset: any,
  target: string,
  helpers: EnumerationHelpers
): void {
  const httpxToolResult = asset.toolResults.find((tr: any) => tr.tool === "httpx");
  const confirmedPorts: Array<{ port: number; service: string; version?: string }> = [];

  if (httpxToolResult?.outputPreview) {
    for (const line of httpxToolResult.outputPreview.split("\n")) {
      try {
        const obj = JSON.parse(line.trim());
        if (obj.status_code && obj.port) {
          const svc = obj.scheme === "https" ? "https" : "http";
          if (!confirmedPorts.find((p) => p.port === obj.port)) {
            confirmedPorts.push({ port: obj.port, service: svc, version: obj.webserver || undefined });
          }
        }
      } catch {
        /* not JSON */
      }
    }
  }

  // Fallback
  if (confirmedPorts.length === 0) {
    const httpxFindingCount = httpxToolResult?.findingCount || 0;
    if (httpxFindingCount > 0) {
      confirmedPorts.push({ port: 80, service: "http" });
      confirmedPorts.push({ port: 443, service: "https" });
    }
  }

  if (confirmedPorts.length > 0) {
    asset.ports = confirmedPorts;
    asset.type = "web_app";
    state.stats.portsFound += confirmedPorts.length;

    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: `🌐 httpx Port Backfill: ${helpers.fmtTarget(asset, target)}`,
      detail: `ScanForge found 0 open ports (cloud firewall), but httpx confirmed ${confirmedPorts.length} live web services: ${confirmedPorts.map((p) => `${p.port}/${p.service}`).join(", ")}. Pipeline will continue with httpx-discovered ports.`,
    });
  }
}
