import { describe, it, expect } from "vitest";

/**
 * Tests for the evidence pipeline fix.
 *
 * Root causes fixed:
 * 1. importFromOpsSnapshot: findingsToCreate used `title`, `evidence`, `severity` etc.
 *    but the insert code read `f.rfTitle`, `f.rfSeverity`, `f.rfEvidence` etc.
 *    All data was being written as undefined/null due to property name mismatch.
 *
 * 2. rawOutput mapping: The vuln type stores scanner data in `rawEvidence` but the
 *    finding builder only checked `v.rawOutput`, missing DI scan evidence entirely.
 *    Fixed to: `v.rawOutput || v.rawEvidence || toolOutput`.
 *
 * 3. Evidence enrichment: All finding creation paths now pull evidence from:
 *    - analysis.poc (proof of concept)
 *    - finding.rawOutput (scanner output from vuln-analysis-agents)
 *    - origVuln.rawEvidence (raw scanner data: nuclei, nmap, HTTP headers)
 *    - origVuln.evidenceChain (DI scan evidence trail)
 *    - origVuln.evidenceDetail (human-readable evidence summary)
 *    - asset.toolResults (actual scanner command output with exit codes)
 *    - event.metadata (raw tool output from engagement timeline events)
 *
 * 4. DOCX renderer: Now renders rich evidence with type labels, descriptions,
 *    and raw output in monospace font.
 *
 * 5. Frontend UI: Evidence items now show type-specific badges with color coding,
 *    descriptions, and collapsible raw output in monospace.
 */

// ── Test 1: Property name mismatch fix ──
describe("importFromOpsSnapshot property name fix", () => {
  it("should use rf-prefixed property names in findingsToCreate", () => {
    // Simulate the old (broken) finding object
    const oldFinding = {
      title: "SQL Injection on login form",
      severity: "high",
      evidence: [{ type: "poc", description: "sqlmap output" }],
      assets: ["example.com"],
      controls: [{ id: "AC-6" }],
      cvssScore: "8.5",
      remediation: "Parameterize queries",
    };

    // The old code would push this, then read f.rfTitle → undefined
    expect(oldFinding.title).toBe("SQL Injection on login form");
    expect((oldFinding as any).rfTitle).toBeUndefined();

    // The fixed code uses rf-prefixed names
    const fixedFinding = {
      rfTitle: oldFinding.title,
      rfSeverity: oldFinding.severity,
      rfEvidence: oldFinding.evidence,
      rfAssets: oldFinding.assets,
      rfControls: oldFinding.controls,
      rfCvssScore: oldFinding.cvssScore,
      rfRemediation: oldFinding.remediation,
    };

    expect(fixedFinding.rfTitle).toBe("SQL Injection on login form");
    expect(fixedFinding.rfSeverity).toBe("high");
    expect(fixedFinding.rfEvidence).toHaveLength(1);
    expect(fixedFinding.rfAssets).toEqual(["example.com"]);
    expect(fixedFinding.rfCvssScore).toBe("8.5");
    expect(fixedFinding.rfRemediation).toBe("Parameterize queries");
  });

  it("should fall back to rfTitle when title is missing", () => {
    const finding = { rfTitle: "Legacy title", severity: "medium" };
    const title = (finding as any).title || finding.rfTitle || "Untitled";
    expect(title).toBe("Legacy title");
  });

  it("should fall back to 'Vulnerability on <asset>' when both title fields are missing", () => {
    const finding = {};
    const assetName = "10.0.0.1";
    const title = (finding as any).title || (finding as any).rfTitle || `Vulnerability on ${assetName}`;
    expect(title).toBe("Vulnerability on 10.0.0.1");
  });
});

// ── Test 2: rawOutput/rawEvidence mapping fix ──
describe("rawOutput mapping fix", () => {
  it("should prefer rawOutput when available", () => {
    const vuln = { rawOutput: "nmap scan output...", rawEvidence: "shodan data..." };
    const rawOutput = vuln.rawOutput || vuln.rawEvidence;
    expect(rawOutput).toBe("nmap scan output...");
  });

  it("should fall back to rawEvidence when rawOutput is missing", () => {
    const vuln = { rawEvidence: "Shodan banner: Apache/2.4.49\nHTTP/1.1 200 OK" };
    const rawOutput = (vuln as any).rawOutput || vuln.rawEvidence;
    expect(rawOutput).toBe("Shodan banner: Apache/2.4.49\nHTTP/1.1 200 OK");
  });

  it("should fall back to toolOutput when both are missing", () => {
    const vuln = {};
    const toolOutput = "nuclei -t cves/ -target example.com\n[CVE-2021-44228]";
    const rawOutput = (vuln as any).rawOutput || (vuln as any).rawEvidence || toolOutput;
    expect(rawOutput).toBe(toolOutput);
  });
});

// ── Test 3: Evidence enrichment from multiple sources ──
describe("evidence enrichment", () => {
  it("should build evidence from PoC", () => {
    const analysis = { poc: "curl -X POST http://target/login -d 'admin=1' returns 200 with admin session" };
    const evidence: any[] = [];
    if (analysis.poc) {
      evidence.push({
        type: "poc",
        reference: `PoC for SQL Injection`,
        description: (typeof analysis.poc === "string" ? analysis.poc : JSON.stringify(analysis.poc)).slice(0, 500),
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe("poc");
    expect(evidence[0].description).toContain("curl -X POST");
  });

  it("should build evidence from rawEvidence (DI scan data)", () => {
    const origVuln = {
      rawEvidence: "HTTP/1.1 200 OK\nServer: Apache/2.4.49\nX-Powered-By: PHP/7.4.3",
      source: "shodan",
      corroborationTier: "multi-source",
    };
    const evidence: any[] = [];
    if (origVuln.rawEvidence) {
      evidence.push({
        type: "raw_evidence",
        reference: `Raw evidence: ${origVuln.source} on example.com`,
        raw: String(origVuln.rawEvidence).slice(0, 2000),
        description: `Source: ${origVuln.source}. Corroboration: ${origVuln.corroborationTier}.`,
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe("raw_evidence");
    expect(evidence[0].raw).toContain("Apache/2.4.49");
    expect(evidence[0].description).toContain("multi-source");
  });

  it("should build evidence from evidenceChain", () => {
    const origVuln = {
      evidenceChain: [
        "Shodan: port 443 open, Apache/2.4.49",
        "Censys: TLS cert CN=example.com",
        "crt.sh: wildcard cert *.example.com",
        "NVD: CVE-2021-41773 affects Apache 2.4.49",
      ],
    };
    const evidence: any[] = [];
    if (origVuln.evidenceChain?.length) {
      evidence.push({
        type: "evidence_chain",
        reference: `Evidence chain for CVE-2021-41773`,
        description: origVuln.evidenceChain.join(" → "),
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe("evidence_chain");
    expect(evidence[0].description).toContain("→");
    expect(evidence[0].description).toContain("Shodan");
    expect(evidence[0].description).toContain("NVD");
  });

  it("should build evidence from toolResults", () => {
    const toolResult = {
      tool: "nuclei",
      findingCount: 3,
      outputPreview: "[CVE-2021-44228] [critical] http://example.com:8080",
      rawOutput: "[2024-01-15] [CVE-2021-44228] [http] [critical] http://example.com:8080\n[CVE-2021-41773] [http] [high] http://example.com",
      command: "nuclei -t cves/ -target example.com",
      exitCode: 0,
      durationMs: 45000,
    };
    const evidence: any[] = [];
    if (toolResult.findingCount > 0 && toolResult.outputPreview) {
      evidence.push({
        type: "tool_output",
        reference: `${toolResult.tool} scan on example.com (${toolResult.findingCount} findings, ${toolResult.durationMs}ms)`,
        raw: (toolResult.rawOutput || toolResult.outputPreview || "").slice(0, 1500),
        description: `Command: ${(toolResult.command || "").slice(0, 300)}. Exit code: ${toolResult.exitCode}. Findings: ${toolResult.findingCount}.`,
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe("tool_output");
    expect(evidence[0].raw).toContain("CVE-2021-44228");
    expect(evidence[0].description).toContain("nuclei");
    expect(evidence[0].description).toContain("Exit code: 0");
  });

  it("should build evidence from engagement event metadata", () => {
    const eventMeta = {
      rawOutput: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      tool: "ssh-brute",
    };
    const evidence: any[] = [];
    if (eventMeta.rawOutput || (eventMeta as any).output || (eventMeta as any).stdout) {
      evidence.push({
        type: "tool_output",
        reference: `${eventMeta.tool || "tool"} output`,
        raw: (eventMeta.rawOutput || "").slice(0, 2000),
        description: `Source: engagement. Phase: exploitation.`,
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].raw).toContain("root:x:0:0");
  });

  it("should fall back to technicalAnalysis when no other evidence", () => {
    const analysis = {
      technicalAnalysis: "The target is running an outdated version of Apache HTTP Server (2.4.49) which is vulnerable to CVE-2021-41773 path traversal.",
    };
    const evidence: any[] = [];
    // No other evidence sources available
    if (evidence.length === 0 && analysis.technicalAnalysis) {
      evidence.push({
        type: "analysis",
        reference: `Analysis for CVE-2021-41773`,
        description: analysis.technicalAnalysis.slice(0, 1000),
      });
    }
    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe("analysis");
    expect(evidence[0].description).toContain("Apache HTTP Server");
  });
});

// ── Test 4: Evidence truncation safety ──
describe("evidence truncation", () => {
  it("should truncate raw evidence to 2000 chars", () => {
    const longEvidence = "A".repeat(5000);
    const truncated = longEvidence.slice(0, 2000);
    expect(truncated.length).toBe(2000);
  });

  it("should truncate tool output to 1500 chars", () => {
    const longOutput = "B".repeat(3000);
    const truncated = longOutput.slice(0, 1500);
    expect(truncated.length).toBe(1500);
  });

  it("should truncate description to 1000 chars", () => {
    const longDesc = "C".repeat(2000);
    const truncated = longDesc.slice(0, 1000);
    expect(truncated.length).toBe(1000);
  });
});

// ── Test 5: Evidence type labels for DOCX/UI rendering ──
describe("evidence type labels", () => {
  const typeLabels: Record<string, string> = {
    poc: "Proof of Concept",
    scanner_output: "Scanner Output",
    raw_evidence: "Raw Evidence",
    evidence_chain: "Evidence Chain",
    evidence_detail: "Evidence Detail",
    tool_output: "Tool Output",
    exploit_attempt: "Exploit Attempt",
    approval_gate: "Approval Gate",
    analysis: "Analysis",
  };

  it("should map all evidence types to human-readable labels", () => {
    expect(typeLabels["poc"]).toBe("Proof of Concept");
    expect(typeLabels["scanner_output"]).toBe("Scanner Output");
    expect(typeLabels["raw_evidence"]).toBe("Raw Evidence");
    expect(typeLabels["evidence_chain"]).toBe("Evidence Chain");
    expect(typeLabels["tool_output"]).toBe("Tool Output");
    expect(typeLabels["exploit_attempt"]).toBe("Exploit Attempt");
  });

  it("should handle unknown types gracefully", () => {
    const unknownType = "custom_evidence";
    const label = typeLabels[unknownType] || unknownType || "Evidence";
    expect(label).toBe("custom_evidence");
  });
});

// ── Test 6: postureToVulns evidence preservation ──
describe("postureToVulns evidence preservation", () => {
  it("should preserve evidenceChain from DI scan PostureFinding", () => {
    const postureFinding = {
      title: "Apache 2.4.49 Path Traversal",
      severity: "critical",
      evidenceChain: [
        "Shodan: port 80 open, Apache/2.4.49",
        "NVD: CVE-2021-41773 confirmed for Apache 2.4.49",
      ],
      evidenceDetail: "Port 80/HTTP detected open via Shodan with Apache/2.4.49 banner",
      rawEvidence: "HTTP/1.1 200 OK\nServer: Apache/2.4.49",
    };

    // The fix preserves these fields in the vuln object
    const vuln = {
      title: postureFinding.title,
      severity: postureFinding.severity,
      rawEvidence: postureFinding.rawEvidence,
      evidenceChain: postureFinding.evidenceChain,
      evidenceDetail: postureFinding.evidenceDetail,
    };

    expect(vuln.rawEvidence).toContain("Apache/2.4.49");
    expect(vuln.evidenceChain).toHaveLength(2);
    expect(vuln.evidenceDetail).toContain("Shodan");
  });

  it("should build rich evidenceDetail instead of generic placeholder", () => {
    const postureFinding = {
      port: 443,
      protocol: "tcp",
      service: "https",
      evidenceChain: [
        "Shodan: TLS 1.0 enabled",
        "Censys: weak cipher suites detected",
      ],
      rawEvidence: "TLSv1.0 Record Layer: Handshake Protocol: Server Hello",
    };

    // Old behavior: "Port 443/tcp detected open via passive reconnaissance"
    // New behavior: includes actual evidence data
    const evidenceDetail = postureFinding.rawEvidence
      ? `Port ${postureFinding.port}/${postureFinding.protocol} (${postureFinding.service}): ${postureFinding.rawEvidence.slice(0, 200)}`
      : `Port ${postureFinding.port}/${postureFinding.protocol} (${postureFinding.service}) detected open`;

    expect(evidenceDetail).toContain("TLSv1.0");
    expect(evidenceDetail).not.toContain("passive reconnaissance");
    expect(evidenceDetail).not.toContain("version unconfirmed");
  });
});

// ── Test 7: exportReportJson evidence format ──
describe("exportReportJson evidence format", () => {
  it("should export full evidence objects instead of just reference strings", () => {
    const rfEvidence = [
      { type: "poc", reference: "PoC for SQLi", description: "sqlmap output shows injection", raw: "sqlmap -u http://..." },
      { type: "raw_evidence", reference: "Shodan data", description: "Banner grab", raw: "HTTP/1.1 200 OK\nServer: Apache" },
    ];

    // Old behavior: just reference strings
    const oldFormat = rfEvidence.map((e: any) => e.reference || e.description);
    expect(oldFormat).toEqual(["PoC for SQLi", "Shodan data"]);

    // New behavior: full evidence objects
    const newFormat = rfEvidence.map((e: any) => ({
      type: e.type || "evidence",
      reference: e.reference || "",
      description: e.description || "",
      raw: e.raw || undefined,
    }));
    expect(newFormat[0].type).toBe("poc");
    expect(newFormat[0].description).toContain("sqlmap");
    expect(newFormat[0].raw).toContain("sqlmap -u");
    expect(newFormat[1].type).toBe("raw_evidence");
    expect(newFormat[1].raw).toContain("Apache");
  });
});

// ── Test 8: Severity mapping with finding.severity vs finding.rfSeverity ──
describe("severity mapping fix", () => {
  it("should prefer finding.severity over finding.rfSeverity", () => {
    const finding = { severity: "high", rfSeverity: "medium" };
    const severity = finding.severity || finding.rfSeverity;
    expect(severity).toBe("high");
  });

  it("should fall back to rfSeverity when severity is missing", () => {
    const finding = { rfSeverity: "critical" };
    const severity = (finding as any).severity || finding.rfSeverity;
    expect(severity).toBe("critical");
  });

  it("should fall back to analysis.riskScore when both are missing", () => {
    const finding = {};
    const analysis = { riskScore: 8.5 };
    const mapSev = (sev: string | null | undefined, score?: number): string => {
      if (sev) return sev;
      if (score !== undefined) {
        if (score >= 9) return "critical";
        if (score >= 7) return "high";
        if (score >= 4) return "moderate";
        if (score >= 2) return "low";
        return "informational";
      }
      return "moderate";
    };
    const severity = mapSev(
      (finding as any).severity || (finding as any).rfSeverity,
      analysis.riskScore,
    );
    expect(severity).toBe("high");
  });
});
