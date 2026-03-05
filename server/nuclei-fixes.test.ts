import { describe, it, expect, vi } from "vitest";

// ─── Test: Nuclei Deduplication Logic ───────────────────────────────────────
describe("Nuclei Phase 3 — Deduplication", () => {
  it("should build dedup keys from severity::title::cve", () => {
    const vulns = [
      { severity: "high", title: "SQL Injection", cve: "CVE-2023-1234" },
      { severity: "medium", title: "XSS Reflected", cve: "" },
      { severity: "critical", title: "RCE via deserialization", cve: "CVE-2024-5678" },
    ];
    const keys = new Set<string>();
    for (const v of vulns) {
      keys.add(`${v.severity}::${v.title}::${v.cve || ""}`);
    }
    expect(keys.size).toBe(3);
    expect(keys.has("high::SQL Injection::CVE-2023-1234")).toBe(true);
    expect(keys.has("medium::XSS Reflected::")).toBe(true);
    expect(keys.has("critical::RCE via deserialization::CVE-2024-5678")).toBe(true);
  });

  it("should detect duplicate findings and skip them", () => {
    const existingKeys = new Set([
      "high::SQL Injection::CVE-2023-1234",
      "medium::XSS Reflected::",
    ]);
    const newFindings = [
      { severity: "high", title: "SQL Injection", cve: "CVE-2023-1234" }, // duplicate
      { severity: "medium", title: "XSS Reflected", cve: "" }, // duplicate
      { severity: "high", title: "SSRF via redirect", cve: "CVE-2024-9999" }, // new
    ];
    let newCount = 0;
    for (const f of newFindings) {
      const key = `${f.severity}::${f.title}::${f.cve || ""}`;
      if (!existingKeys.has(key)) {
        existingKeys.add(key);
        newCount++;
      }
    }
    expect(newCount).toBe(1);
    expect(existingKeys.size).toBe(3);
  });

  it("should handle empty CVE fields correctly in dedup", () => {
    const keys = new Set<string>();
    const findings = [
      { severity: "high", title: "Open Redirect", cve: undefined },
      { severity: "high", title: "Open Redirect", cve: "" },
      { severity: "high", title: "Open Redirect", cve: null },
    ];
    for (const f of findings) {
      keys.add(`${f.severity}::${f.title}::${f.cve || ""}`);
    }
    // All three should collapse to the same key
    expect(keys.size).toBe(1);
  });

  it("should allow same title with different severity as separate findings", () => {
    const keys = new Set<string>();
    const findings = [
      { severity: "high", title: "Missing HSTS", cve: "" },
      { severity: "medium", title: "Missing HSTS", cve: "" },
    ];
    for (const f of findings) {
      keys.add(`${f.severity}::${f.title}::${f.cve || ""}`);
    }
    expect(keys.size).toBe(2);
  });
});

// ─── Test: Accurate Phase 3 Summary Message ─────────────────────────────────
describe("Nuclei Phase 3 — Accurate Summary", () => {
  it("should track phase3-specific findings separately from total", () => {
    const vulnsBeforePhase3 = 95; // From targeted_enum
    let totalVulns = 95;
    let phase3NucleiFindings = 0;

    // Simulate Phase 3 finding 3 new vulns
    const phase3Results = [
      { severity: "high", title: "New CVE found", cve: "CVE-2025-0001" },
      { severity: "medium", title: "Info disclosure", cve: "" },
      { severity: "critical", title: "RCE", cve: "CVE-2025-0002" },
    ];
    for (const _f of phase3Results) {
      totalVulns++;
      phase3NucleiFindings++;
    }

    expect(phase3NucleiFindings).toBe(3);
    expect(totalVulns).toBe(98);
    expect(vulnsBeforePhase3).toBe(95);

    // The summary message should say "3 new" not "98 total"
    const summary = `Phase 3 nuclei found ${phase3NucleiFindings} new vulnerabilities across 2 targets. Total vulns: ${totalVulns} (${vulnsBeforePhase3} from prior phases + ${phase3NucleiFindings} new)`;
    expect(summary).toContain("3 new vulnerabilities");
    expect(summary).toContain("95 from prior phases");
    expect(summary).toContain("Total vulns: 98");
  });

  it("should report SSH errors in summary when scans fail", () => {
    let phase3NucleiErrors = 0;
    const nucleiAssets = [{ hostname: "target1" }, { hostname: "target2" }];

    // Simulate 2 SSH failures
    phase3NucleiErrors = 2;

    const errorNote = phase3NucleiErrors > 0
      ? ` (${phase3NucleiErrors} scans failed — SSH connection issues)`
      : "";
    const summary = `Phase 3 nuclei found 0 new vulnerabilities across ${nucleiAssets.length} targets${errorNote}`;
    expect(summary).toContain("2 scans failed");
    expect(summary).toContain("SSH connection issues");
  });

  it("should not mention SSH errors when all scans succeed", () => {
    const phase3NucleiErrors = 0;
    const errorNote = phase3NucleiErrors > 0
      ? ` (${phase3NucleiErrors} scans failed — SSH connection issues)`
      : "";
    expect(errorNote).toBe("");
  });
});

// ─── Test: SSH Retry Logic ──────────────────────────────────────────────────
describe("Nuclei Phase 3 — SSH Retry Logic", () => {
  it("should identify SSH failures by exit code -1, empty stdout, and short duration", () => {
    const result = { exitCode: -1, stdout: "", durationMs: 15000, error: "SSH connection error" };
    const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
    expect(isSSHFailure).toBe(true);
  });

  it("should NOT retry when exit code is 0 (success)", () => {
    const result = { exitCode: 0, stdout: "some output", durationMs: 5000 };
    const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
    expect(isSSHFailure).toBe(false);
  });

  it("should NOT retry when there IS stdout (real timeout, not SSH failure)", () => {
    const result = { exitCode: -1, stdout: "partial output before timeout", durationMs: 600000 };
    const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
    expect(isSSHFailure).toBe(false);
  });

  it("should NOT retry when duration is long (real tool timeout, not SSH)", () => {
    const result = { exitCode: -1, stdout: "", durationMs: 300000 };
    const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
    expect(isSSHFailure).toBe(false);
  });

  it("should retry up to maxRetries times on SSH failure", async () => {
    let attempts = 0;
    const maxRetries = 2;

    async function executeWithRetry(): Promise<{ stdout: string; exitCode: number }> {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        attempts++;
        const result = { exitCode: -1, stdout: "", durationMs: 15000 };
        const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
        if (isSSHFailure && attempt < maxRetries) {
          continue; // retry
        }
        return result;
      }
      return { stdout: "", exitCode: -1 };
    }

    const result = await executeWithRetry();
    expect(attempts).toBe(3); // 1 initial + 2 retries
    expect(result.exitCode).toBe(-1);
  });

  it("should stop retrying on success", async () => {
    let attempts = 0;
    const maxRetries = 2;

    async function executeWithRetry(): Promise<{ stdout: string; exitCode: number }> {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        attempts++;
        // Succeed on second attempt
        if (attempt === 1) {
          return { stdout: '{"matched-at":"http://target"}', exitCode: 0 };
        }
        const result = { exitCode: -1, stdout: "", durationMs: 15000 };
        const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 20000;
        if (isSSHFailure && attempt < maxRetries) {
          continue;
        }
        return result;
      }
      return { stdout: "", exitCode: -1 };
    }

    const result = await executeWithRetry();
    expect(attempts).toBe(2); // 1 failed + 1 success
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("matched-at");
  });
});

// ─── Test: SSH Connection Pool Logic ────────────────────────────────────────
describe("SSH Connection Pool", () => {
  it("should reuse pooled connection when available", () => {
    let pooledConn: { ready: boolean } | null = null;
    let pooledConnReady = false;
    let freshConnections = 0;

    function getConnection() {
      if (pooledConn && pooledConnReady) {
        return pooledConn; // reuse
      }
      freshConnections++;
      pooledConn = { ready: true };
      pooledConnReady = true;
      return pooledConn;
    }

    // First call creates fresh connection
    const conn1 = getConnection();
    expect(freshConnections).toBe(1);

    // Second call reuses
    const conn2 = getConnection();
    expect(freshConnections).toBe(1);
    expect(conn2).toBe(conn1);
  });

  it("should create new connection when pool is empty", () => {
    let pooledConn: object | null = null;
    let pooledConnReady = false;
    let freshConnections = 0;

    function getConnection() {
      if (pooledConn && pooledConnReady) {
        return pooledConn;
      }
      freshConnections++;
      pooledConn = { ready: true };
      pooledConnReady = true;
      return pooledConn;
    }

    const conn = getConnection();
    expect(freshConnections).toBe(1);
    expect(conn).toBeTruthy();
  });

  it("should recreate connection after pool is closed", () => {
    let pooledConn: object | null = { ready: true };
    let pooledConnReady = true;
    let freshConnections = 0;

    function closePool() {
      pooledConn = null;
      pooledConnReady = false;
    }

    function getConnection() {
      if (pooledConn && pooledConnReady) {
        return pooledConn;
      }
      freshConnections++;
      pooledConn = { ready: true };
      pooledConnReady = true;
      return pooledConn;
    }

    // Reuse existing
    const conn1 = getConnection();
    expect(freshConnections).toBe(0);

    // Close pool
    closePool();

    // Should create new
    const conn2 = getConnection();
    expect(freshConnections).toBe(1);
    expect(conn2).not.toBe(conn1);
  });

  it("should fall back to fresh connection when pooled exec fails", async () => {
    let usedPooled = false;
    let usedFresh = false;

    async function executeWithPool(command: string): Promise<string> {
      try {
        usedPooled = true;
        throw new Error("SSH pool connection error: channel open failed");
      } catch (poolErr: any) {
        if (!poolErr.message.includes("timed out")) {
          usedFresh = true;
          return "fresh connection output";
        }
        throw poolErr;
      }
    }

    const result = await executeWithPool("nuclei -u http://target");
    expect(usedPooled).toBe(true);
    expect(usedFresh).toBe(true);
    expect(result).toBe("fresh connection output");
  });

  it("should NOT fall back on timeout errors (propagate timeout)", async () => {
    async function executeWithPool(): Promise<string> {
      try {
        throw new Error("SSH command timed out after 600s");
      } catch (poolErr: any) {
        if (!poolErr.message.includes("timed out")) {
          return "fresh connection output";
        }
        throw poolErr;
      }
    }

    await expect(executeWithPool()).rejects.toThrow("timed out");
  });
});

// ─── Test: LLM Context Enrichment ──────────────────────────────────────────
describe("LLM Context — Tool Result Enrichment", () => {
  it("should include tool_result entries in allFindingsForLLM", () => {
    const asset = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [
        { title: "SQL Injection", severity: "high", cve: "CVE-2023-1234" },
      ],
      ports: [{ port: 443, service: "https", version: "nginx 1.24" }],
      zapFindings: [],
      toolResults: [
        {
          tool: "nuclei",
          findingCount: 5,
          exitCode: 0,
          phase: "targeted_enum",
          outputPreview: '{"matched-at":"http://target.com","info":{"severity":"high"}}',
        },
        {
          tool: "nikto",
          findingCount: 3,
          exitCode: 0,
          phase: "targeted_enum",
          outputPreview: "+ Server: nginx/1.24\n+ /admin: Admin page found",
        },
        {
          tool: "gobuster",
          findingCount: 0,
          exitCode: 0,
          phase: "targeted_enum",
          outputPreview: "",
        },
      ],
    };

    // Simulate the enrichment logic from the orchestrator
    const toolResultEntries = (asset.toolResults || [])
      .filter((tr: any) => tr.findingCount > 0 || tr.outputPreview)
      .map((tr: any) => ({
        type: "tool_result",
        title: `[${tr.tool}] ${tr.findingCount} findings (exit ${tr.exitCode}, ${tr.phase})`,
        severity: tr.findingCount > 0 ? "info" : "low",
        target: asset.hostname,
        host: asset.ip || asset.hostname,
        details: tr.outputPreview
          ? tr.outputPreview.slice(0, 500)
          : `${tr.tool} ran with ${tr.findingCount} findings`,
        tool: tr.tool,
        phase: tr.phase,
      }));

    // nuclei (5 findings + output) and nikto (3 findings + output) should be included
    // gobuster (0 findings, no output) should be excluded
    expect(toolResultEntries.length).toBe(2);
    expect(toolResultEntries[0].tool).toBe("nuclei");
    expect(toolResultEntries[0].type).toBe("tool_result");
    expect(toolResultEntries[0].details).toContain("matched-at");
    expect(toolResultEntries[1].tool).toBe("nikto");
    expect(toolResultEntries[1].details).toContain("Admin page found");
  });

  it("should enrich vuln analysis findings with tool output context", () => {
    const toolResults = [
      {
        tool: "nuclei",
        findingCount: 2,
        outputPreview: '{"matched-at":"http://target","template-id":"cve-2023-1234"}',
      },
      {
        tool: "nikto",
        findingCount: 1,
        outputPreview: "+ OSVDB-3092: /admin/: Admin directory found",
      },
    ];

    // Build lookup
    const toolOutputMap = new Map<string, string>();
    for (const tr of toolResults) {
      if (tr.outputPreview && tr.findingCount > 0) {
        const existing = toolOutputMap.get(tr.tool) || "";
        toolOutputMap.set(tr.tool, (existing + "\n" + tr.outputPreview).slice(0, 2000));
      }
    }

    expect(toolOutputMap.has("nuclei")).toBe(true);
    expect(toolOutputMap.has("nikto")).toBe(true);
    expect(toolOutputMap.get("nuclei")).toContain("cve-2023-1234");

    // Simulate matching a vuln title to a tool
    const vulnTitle = "[nuclei] SQL Injection CVE-2023-1234";
    const toolMatch = vulnTitle.match(/^\[(\w+)\]/)?.[1]?.toLowerCase();
    expect(toolMatch).toBe("nuclei");
    const toolOutput = toolMatch ? toolOutputMap.get(toolMatch) : undefined;
    expect(toolOutput).toContain("cve-2023-1234");
  });

  it("should handle vulns without tool prefix gracefully", () => {
    const vulnTitle = "Missing HSTS Header";
    const toolMatch = vulnTitle.match(/^\[(\w+)\]/)?.[1]?.toLowerCase();
    expect(toolMatch).toBeUndefined();
  });
});
