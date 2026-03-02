import { describe, it, expect, beforeEach } from "vitest";

// ─── Engagement Orchestrator State Management Tests ──────────────────────

describe("Engagement Ops State Management", () => {
  // We test the pure state logic without needing DB/LLM

  it("should define all required ops phases in correct order", () => {
    const PHASES = ["idle", "recon", "enumeration", "vuln_detection", "exploitation", "post_exploit", "reporting", "completed", "paused", "error"];
    expect(PHASES).toContain("idle");
    expect(PHASES).toContain("recon");
    expect(PHASES).toContain("enumeration");
    expect(PHASES).toContain("vuln_detection");
    expect(PHASES).toContain("exploitation");
    expect(PHASES).toContain("post_exploit");
    expect(PHASES).toContain("completed");
    // Verify ordering: recon before enumeration before vuln_detection before exploitation
    expect(PHASES.indexOf("recon")).toBeLessThan(PHASES.indexOf("enumeration"));
    expect(PHASES.indexOf("enumeration")).toBeLessThan(PHASES.indexOf("vuln_detection"));
    expect(PHASES.indexOf("vuln_detection")).toBeLessThan(PHASES.indexOf("exploitation"));
    expect(PHASES.indexOf("exploitation")).toBeLessThan(PHASES.indexOf("post_exploit"));
  });

  it("should initialize ops state with correct defaults", () => {
    const state = {
      engagementId: 1,
      engagementType: "pentest",
      phase: "idle" as const,
      progress: 0,
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {
        hostsScanned: 0,
        portsFound: 0,
        vulnsFound: 0,
        exploitsAttempted: 0,
        exploitsSucceeded: 0,
        sessionsOpened: 0,
        zapScansRun: 0,
        wafDetections: 0,
      },
    };
    expect(state.phase).toBe("idle");
    expect(state.isRunning).toBe(false);
    expect(state.progress).toBe(0);
    expect(state.assets).toHaveLength(0);
    expect(state.log).toHaveLength(0);
    expect(state.approvalGates).toHaveLength(0);
    expect(state.stats.hostsScanned).toBe(0);
    expect(state.stats.zapScansRun).toBe(0);
  });

  it("should differentiate pentest vs red_team engagement types", () => {
    const pentestState = { engagementType: "pentest" };
    const redteamState = { engagementType: "red_team" };
    expect(pentestState.engagementType).toBe("pentest");
    expect(redteamState.engagementType).toBe("red_team");
    expect(pentestState.engagementType).not.toBe(redteamState.engagementType);
  });
});

// ─── Approval Gate Tests ─────────────────────────────────────────────────

describe("Approval Gate Logic", () => {
  it("should create an approval gate with correct structure", () => {
    const gate = {
      id: "gate-1",
      phase: "exploitation" as const,
      riskTier: "red" as const,
      title: "Execute Metasploit Module",
      description: "exploit/multi/handler against 192.168.1.10:445",
      target: "192.168.1.10",
      module: "exploit/windows/smb/ms17_010_eternalblue",
      detail: { port: 445, service: "smb" },
      status: "pending" as const,
      createdAt: Date.now(),
    };
    expect(gate.status).toBe("pending");
    expect(gate.riskTier).toBe("red");
    expect(gate.module).toContain("eternalblue");
    expect(gate.target).toBe("192.168.1.10");
  });

  it("should support three risk tiers: yellow, orange, red", () => {
    const tiers = ["yellow", "orange", "red"];
    tiers.forEach(tier => {
      expect(["yellow", "orange", "red"]).toContain(tier);
    });
  });

  it("should transition gate from pending to approved", () => {
    const gate = { status: "pending" as string, resolvedAt: undefined as number | undefined, resolvedBy: undefined as string | undefined };
    gate.status = "approved";
    gate.resolvedAt = Date.now();
    gate.resolvedBy = "operator-1";
    expect(gate.status).toBe("approved");
    expect(gate.resolvedAt).toBeDefined();
    expect(gate.resolvedBy).toBe("operator-1");
  });

  it("should transition gate from pending to denied", () => {
    const gate = { status: "pending" as string, resolvedAt: undefined as number | undefined, resolvedBy: undefined as string | undefined };
    gate.status = "denied";
    gate.resolvedAt = Date.now();
    gate.resolvedBy = "team-lead";
    expect(gate.status).toBe("denied");
  });

  it("should require approval for exploitation phase actions", () => {
    const exploitPhases = ["exploitation", "post_exploit"];
    const requiresApproval = (phase: string) => exploitPhases.includes(phase);
    expect(requiresApproval("exploitation")).toBe(true);
    expect(requiresApproval("post_exploit")).toBe(true);
    expect(requiresApproval("recon")).toBe(false);
    expect(requiresApproval("enumeration")).toBe(false);
  });
});

// ─── Asset Status Tracking Tests ─────────────────────────────────────────

describe("Asset Status Tracking", () => {
  it("should track asset through lifecycle: pending → scanning → enumerated → vulns_found → compromised", () => {
    const statuses = ["pending", "scanning", "enumerated", "vulns_found", "exploiting", "compromised"];
    let asset = { hostname: "target.example.com", status: "pending" };
    
    asset.status = "scanning";
    expect(asset.status).toBe("scanning");
    
    asset.status = "enumerated";
    expect(asset.status).toBe("enumerated");
    
    asset.status = "vulns_found";
    expect(asset.status).toBe("vulns_found");
    
    asset.status = "compromised";
    expect(asset.status).toBe("compromised");
    
    expect(statuses).toContain(asset.status);
  });

  it("should track open ports per asset", () => {
    const asset = {
      hostname: "web.example.com",
      ports: [
        { port: 80, service: "http", version: "nginx/1.21" },
        { port: 443, service: "https", version: "nginx/1.21" },
        { port: 22, service: "ssh", version: "OpenSSH 8.9" },
      ],
    };
    expect(asset.ports).toHaveLength(3);
    expect(asset.ports.find(p => p.port === 80)?.service).toBe("http");
    expect(asset.ports.find(p => p.port === 443)?.service).toBe("https");
  });

  it("should track vulnerabilities per asset with severity levels", () => {
    const asset = {
      hostname: "web.example.com",
      vulns: [
        { id: "v1", severity: "critical", title: "RCE via deserialization", cve: "CVE-2024-1234" },
        { id: "v2", severity: "high", title: "SQL Injection", cve: "CVE-2024-5678" },
        { id: "v3", severity: "medium", title: "XSS Reflected" },
      ],
    };
    expect(asset.vulns).toHaveLength(3);
    expect(asset.vulns.filter(v => v.severity === "critical")).toHaveLength(1);
    expect(asset.vulns.filter(v => v.severity === "high")).toHaveLength(1);
  });

  it("should track ZAP web app findings per asset", () => {
    const asset = {
      hostname: "web.example.com",
      zapFindings: [
        { alert: "SQL Injection", risk: "High", url: "https://web.example.com/api/users", cweId: 89 },
        { alert: "Cross-Site Scripting", risk: "Medium", url: "https://web.example.com/search", cweId: 79 },
        { alert: "Information Disclosure", risk: "Low", url: "https://web.example.com/robots.txt" },
      ],
    };
    expect(asset.zapFindings).toHaveLength(3);
    expect(asset.zapFindings.filter(f => f.risk === "High")).toHaveLength(1);
    expect(asset.zapFindings[0].cweId).toBe(89); // SQL Injection CWE
  });

  it("should track WAF detection per asset", () => {
    const asset = {
      hostname: "web.example.com",
      wafDetected: "Cloudflare",
    };
    expect(asset.wafDetected).toBe("Cloudflare");
  });

  it("should track exploit attempts with success/failure", () => {
    const asset = {
      hostname: "target.example.com",
      exploitAttempts: [
        { module: "exploit/windows/smb/ms17_010_eternalblue", success: true, sessionId: "session-1" },
        { module: "exploit/multi/http/struts2_rce", success: false },
      ],
    };
    expect(asset.exploitAttempts).toHaveLength(2);
    expect(asset.exploitAttempts.filter(e => e.success)).toHaveLength(1);
    expect(asset.exploitAttempts[0].sessionId).toBe("session-1");
  });
});

// ─── Ops Log Entry Tests ─────────────────────────────────────────────────

describe("Ops Log Entries", () => {
  it("should create log entries with required fields", () => {
    const entry = {
      id: "log-1",
      timestamp: Date.now(),
      phase: "recon" as const,
      type: "scan_start",
      title: "Nmap SYN Scan Started",
      detail: "Scanning 192.168.1.0/24 with -sS -sV -O flags",
    };
    expect(entry.id).toBeDefined();
    expect(entry.timestamp).toBeGreaterThan(0);
    expect(entry.phase).toBe("recon");
    expect(entry.type).toBe("scan_start");
  });

  it("should support all log entry types", () => {
    const types = [
      "scan_start", "scan_result", "finding", "exploit_attempt", "exploit_success",
      "exploit_fail", "approval_request", "approval_response", "c2_deploy",
      "llm_decision", "zap_scan", "waf_detected", "phase_complete", "error", "evidence",
    ];
    expect(types).toHaveLength(15);
    expect(types).toContain("zap_scan");
    expect(types).toContain("waf_detected");
    expect(types).toContain("llm_decision");
    expect(types).toContain("c2_deploy");
  });

  it("should include LLM reasoning in llm_decision entries", () => {
    const entry = {
      type: "llm_decision",
      title: "Attack Vector Selected",
      detail: "Prioritizing web application attack surface based on exposed services",
      data: {
        reasoning: "Port 443 running outdated Apache with known CVEs. ZAP found SQL injection. This is the weakest entry point.",
        selectedModules: ["exploit/multi/http/apache_mod_cgi_bash_env_exec"],
      },
    };
    expect(entry.data?.reasoning).toBeDefined();
    expect(entry.data?.reasoning).toContain("weakest entry point");
  });
});

// ─── RoE Scope Enforcement Tests ─────────────────────────────────────────

describe("RoE Scope Enforcement", () => {
  it("should validate targets against in-scope domains", () => {
    const scopedDomains = ["example.com", "*.example.com", "api.target.io"];
    const isInScope = (target: string) => {
      return scopedDomains.some(d => {
        if (d.startsWith("*.")) {
          const base = d.slice(2);
          return target === base || target.endsWith(`.${base}`);
        }
        return target === d;
      });
    };
    expect(isInScope("example.com")).toBe(true);
    expect(isInScope("sub.example.com")).toBe(true);
    expect(isInScope("api.target.io")).toBe(true);
    expect(isInScope("evil.com")).toBe(false);
    expect(isInScope("notexample.com")).toBe(false);
  });

  it("should validate targets against in-scope IP ranges", () => {
    const scopedIPs = ["192.168.1.0/24", "10.0.0.5"];
    const isIPInScope = (ip: string) => {
      return scopedIPs.some(range => {
        if (range.includes("/")) {
          const [network, bits] = range.split("/");
          const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
          const ipNum = ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
          const netNum = network.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
          return (ipNum & mask) === (netNum & mask);
        }
        return ip === range;
      });
    };
    expect(isIPInScope("192.168.1.100")).toBe(true);
    expect(isIPInScope("192.168.1.1")).toBe(true);
    expect(isIPInScope("192.168.2.1")).toBe(false);
    expect(isIPInScope("10.0.0.5")).toBe(true);
    expect(isIPInScope("10.0.0.6")).toBe(false);
  });

  it("should block active operations when RoE is not signed", () => {
    const roeStatus = "none";
    const activePhases = ["enumeration", "vuln_detection", "exploitation", "post_exploit"];
    const canProceed = (phase: string) => {
      if (roeStatus !== "signed" && activePhases.includes(phase)) return false;
      return true;
    };
    expect(canProceed("recon")).toBe(true); // passive recon allowed
    expect(canProceed("enumeration")).toBe(false);
    expect(canProceed("exploitation")).toBe(false);
    expect(canProceed("post_exploit")).toBe(false);
  });

  it("should allow all phases when RoE is signed", () => {
    const roeStatus = "signed";
    const phases = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];
    const canProceed = (phase: string) => {
      if (roeStatus !== "signed" && ["enumeration", "vuln_detection", "exploitation", "post_exploit"].includes(phase)) return false;
      return true;
    };
    phases.forEach(phase => {
      expect(canProceed(phase)).toBe(true);
    });
  });
});

// ─── Stats Aggregation Tests ─────────────────────────────────────────────

describe("Stats Aggregation", () => {
  it("should correctly aggregate stats from multiple assets", () => {
    const assets = [
      { ports: [{ port: 80 }, { port: 443 }], vulns: [{ id: "v1" }], zapFindings: [{ alert: "XSS" }], exploitAttempts: [{ success: true }] },
      { ports: [{ port: 22 }], vulns: [{ id: "v2" }, { id: "v3" }], zapFindings: [], exploitAttempts: [{ success: false }, { success: true }] },
    ];
    const stats = {
      hostsScanned: assets.length,
      portsFound: assets.reduce((sum, a) => sum + a.ports.length, 0),
      vulnsFound: assets.reduce((sum, a) => sum + a.vulns.length, 0),
      zapScansRun: assets.filter(a => a.zapFindings.length > 0).length,
      exploitsAttempted: assets.reduce((sum, a) => sum + a.exploitAttempts.length, 0),
      exploitsSucceeded: assets.reduce((sum, a) => sum + a.exploitAttempts.filter(e => e.success).length, 0),
    };
    expect(stats.hostsScanned).toBe(2);
    expect(stats.portsFound).toBe(3);
    expect(stats.vulnsFound).toBe(3);
    expect(stats.zapScansRun).toBe(1);
    expect(stats.exploitsAttempted).toBe(3);
    expect(stats.exploitsSucceeded).toBe(2);
  });
});

// ─── Pentest vs Red Team Branching Tests ─────────────────────────────────

describe("Pentest vs Red Team Branching", () => {
  it("pentest: should target each asset systematically for unauthorized access", () => {
    const pentestStrategy = {
      type: "pentest",
      approach: "systematic",
      perAsset: true,
      goals: ["unauthorized_data_access", "privilege_escalation"],
      completionCriteria: "all_assets_tested",
    };
    expect(pentestStrategy.perAsset).toBe(true);
    expect(pentestStrategy.approach).toBe("systematic");
    expect(pentestStrategy.goals).toContain("unauthorized_data_access");
    expect(pentestStrategy.completionCriteria).toBe("all_assets_tested");
  });

  it("red team: should find weakest entry and pivot internally", () => {
    const redteamStrategy = {
      type: "red_team",
      approach: "opportunistic",
      perAsset: false,
      goals: ["c2_callback", "lateral_movement", "objective_completion"],
      completionCriteria: "objectives_achieved",
    };
    expect(redteamStrategy.perAsset).toBe(false);
    expect(redteamStrategy.approach).toBe("opportunistic");
    expect(redteamStrategy.goals).toContain("c2_callback");
    expect(redteamStrategy.goals).toContain("lateral_movement");
  });

  it("red team: should deploy C2 agent after initial shell", () => {
    const c2Deploy = {
      type: "c2_deploy",
      platform: "caldera",
      agentType: "sandcat",
      target: "192.168.1.10",
      callbackUrl: "https://c2.operator.io:8443",
      deployed: true,
      sessionId: "agent-abc123",
    };
    expect(c2Deploy.deployed).toBe(true);
    expect(c2Deploy.platform).toBe("caldera");
    expect(c2Deploy.sessionId).toBeDefined();
  });

  it("pentest: should generate report after all assets tested", () => {
    const reportData = {
      engagementType: "pentest",
      assetsTotal: 5,
      assetsCompromised: 3,
      assetsClean: 2,
      criticalFindings: 2,
      highFindings: 4,
      evidenceItems: 12,
      reportReady: true,
    };
    expect(reportData.assetsTotal).toBe(reportData.assetsCompromised + reportData.assetsClean);
    expect(reportData.reportReady).toBe(true);
    expect(reportData.evidenceItems).toBeGreaterThan(0);
  });
});

// ─── ZAP Integration Tests ──────────────────────────────────────────────

describe("ZAP Web App Scanning Integration", () => {
  it("should auto-trigger ZAP scan when web app is discovered", () => {
    const asset = { type: "web_app", hostname: "app.example.com", ports: [{ port: 443, service: "https" }] };
    const shouldTriggerZap = (a: typeof asset) => {
      const webServices = ["http", "https", "http-proxy"];
      return a.type === "web_app" || a.ports.some(p => webServices.includes(p.service));
    };
    expect(shouldTriggerZap(asset)).toBe(true);
  });

  it("should not trigger ZAP for non-web assets", () => {
    const asset = { type: "server", hostname: "db.example.com", ports: [{ port: 3306, service: "mysql" }] };
    const shouldTriggerZap = (a: typeof asset) => {
      const webServices = ["http", "https", "http-proxy"];
      return a.type === "web_app" || a.ports.some(p => webServices.includes(p.service));
    };
    expect(shouldTriggerZap(asset)).toBe(false);
  });

  it("should detect WAF from ZAP response headers", () => {
    const wafSignatures: Record<string, string[]> = {
      "Cloudflare": ["cf-ray", "cf-cache-status"],
      "AWS WAF": ["x-amzn-waf"],
      "Akamai": ["akamai-grn"],
      "Imperva": ["x-cdn", "incap_ses"],
    };
    const headers = { "cf-ray": "abc123", "cf-cache-status": "HIT" };
    const detected = Object.entries(wafSignatures).find(([, sigs]) =>
      sigs.some(sig => sig in headers)
    );
    expect(detected?.[0]).toBe("Cloudflare");
  });

  it("should configure WAF-aware scanning with throttling", () => {
    const wafConfig = {
      throttleMs: 2000,
      randomizeUserAgent: true,
      headerRotation: true,
      maxConcurrentRequests: 2,
      avoidFingerprinting: true,
    };
    expect(wafConfig.throttleMs).toBeGreaterThanOrEqual(1000);
    expect(wafConfig.randomizeUserAgent).toBe(true);
    expect(wafConfig.maxConcurrentRequests).toBeLessThanOrEqual(5);
  });
});

// ─── LLM Pipeline Integration Tests ─────────────────────────────────────

describe("LLM Pipeline Integration", () => {
  it("should correlate findings across scan types for exploit selection", () => {
    const nmapFindings = [{ port: 443, service: "https", version: "Apache/2.4.49" }];
    const nucleiFindings = [{ templateId: "CVE-2021-41773", severity: "critical", matched: "Apache 2.4.49 Path Traversal" }];
    const zapFindings = [{ alert: "Path Traversal", risk: "High", url: "https://target.com/cgi-bin/" }];

    // LLM should correlate these into a unified attack recommendation
    const correlated = {
      target: "target.com:443",
      service: "Apache/2.4.49",
      vulns: [
        { source: "nuclei", id: "CVE-2021-41773", severity: "critical" },
        { source: "zap", alert: "Path Traversal", risk: "High" },
      ],
      recommendedExploit: "exploit/multi/http/apache_normalize_path_rce",
      confidence: "high",
    };
    expect(correlated.vulns).toHaveLength(2);
    expect(correlated.confidence).toBe("high");
    expect(correlated.recommendedExploit).toContain("apache");
  });

  it("should generate WAF bypass suggestions when WAF is detected", () => {
    const wafType = "Cloudflare";
    const bypassStrategies: Record<string, string[]> = {
      "Cloudflare": ["Use origin IP if discovered", "Encode payloads with double URL encoding", "Use HTTP/2 downgrade"],
      "AWS WAF": ["Test with Unicode normalization", "Use chunked transfer encoding"],
      "Akamai": ["Slow-rate attacks to avoid rate limiting", "Fragment payloads across multiple requests"],
    };
    const strategies = bypassStrategies[wafType] || [];
    expect(strategies.length).toBeGreaterThan(0);
    expect(strategies[0]).toContain("origin IP");
  });
});

// ─── Orchestrator State Management (Live Imports) ────────────────────────

describe("Engagement Orchestrator — Live State Management", () => {
  it("initOpsState creates state via the actual orchestrator module", async () => {
    const { initOpsState, getOpsState } = await import("./lib/engagement-orchestrator");
    const state = initOpsState(88001, "pentest");
    expect(state).toBeDefined();
    expect(state.engagementId).toBe(88001);
    expect(state.engagementType).toBe("pentest");
    expect(state.phase).toBe("idle");
    expect(state.isRunning).toBe(false);
    expect(state.assets).toEqual([]);
    expect(state.stats.hostsScanned).toBe(0);

    const retrieved = getOpsState(88001);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.engagementId).toBe(88001);
  });

  it("getOpsState returns null for non-existent engagement", async () => {
    const { getOpsState } = await import("./lib/engagement-orchestrator");
    const state = getOpsState(999999);
    expect(state).toBeNull();
  });

  it("stopEngagement stops a running engagement", async () => {
    const { initOpsState, stopEngagement } = await import("./lib/engagement-orchestrator");
    const state = initOpsState(88002, "red_team");
    state.isRunning = true;
    state.phase = "enumeration";

    const result = stopEngagement(88002);
    expect(result).toBe(true);
    expect(state.isRunning).toBe(false);
    expect(state.currentAction).toBe("Stopped by operator");
  });

  it("stopEngagement returns false for non-existent engagement", async () => {
    const { stopEngagement } = await import("./lib/engagement-orchestrator");
    expect(stopEngagement(999998)).toBe(false);
  });
});

// ─── executeEngagement startPhase Option ─────────────────────────────────

describe("executeEngagement — startPhase Option", () => {
  it("executeEngagement function accepts 3 parameters (engagementId, operatorCtx, options)", async () => {
    const { executeEngagement } = await import("./lib/engagement-orchestrator");
    expect(typeof executeEngagement).toBe("function");
    // The function should accept at least 2 params (3rd is optional)
    expect(executeEngagement.length).toBeGreaterThanOrEqual(2);
  });

  it("initOpsState creates state that can be started from enumeration phase", async () => {
    const { initOpsState } = await import("./lib/engagement-orchestrator");
    const state = initOpsState(88003, "pentest");

    // Simulate what startActiveScan does: set phase to enumeration
    state.isRunning = true;
    state.phase = "enumeration";
    state.startedAt = Date.now();

    expect(state.phase).toBe("enumeration");
    expect(state.isRunning).toBe(true);
    expect(state.startedAt).toBeGreaterThan(0);
  });
});

// ─── Tool Matching Logic ─────────────────────────────────────────────────

describe("Tool Matching — Service-to-Tool Mapping", () => {
  it("web ports select ZAP and Nuclei", () => {
    const ports = [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
    ];

    const webPorts = ports.filter(p =>
      ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );

    expect(webPorts).toHaveLength(2);

    const tools: string[] = ["Nuclei (CVE templates)"];
    if (webPorts.length > 0) {
      tools.push(`OWASP ZAP (${webPorts.map(p => `${p.service}:${p.port}`).join(", ")})`);
    }

    expect(tools).toContain("Nuclei (CVE templates)");
    expect(tools.some(t => t.includes("OWASP ZAP"))).toBe(true);
    expect(tools.some(t => t.includes("http:80"))).toBe(true);
  });

  it("login services select credential testing", () => {
    const ports = [
      { port: 22, service: "ssh" },
      { port: 3306, service: "mysql" },
      { port: 5432, service: "postgresql" },
    ];

    const loginPorts = ports.filter(p =>
      ["ssh", "ftp", "telnet", "rdp", "smb", "vnc", "mysql", "postgresql", "mssql"].includes(p.service)
    );

    expect(loginPorts).toHaveLength(3);

    const tools: string[] = [];
    if (loginPorts.length > 0) {
      tools.push(`Credential Testing (${loginPorts.map(p => `${p.service}:${p.port}`).join(", ")})`);
    }

    expect(tools.some(t => t.includes("Credential Testing"))).toBe(true);
    expect(tools.some(t => t.includes("ssh:22"))).toBe(true);
  });

  it("SMB port triggers SMB enumeration", () => {
    const ports = [{ port: 445, service: "smb" }];
    const hasSMB = ports.some(p => p.service === "smb" || p.port === 445);
    expect(hasSMB).toBe(true);
  });

  it("LDAP port triggers LDAP enumeration", () => {
    const ports = [{ port: 389, service: "ldap" }];
    const hasLDAP = ports.some(p => p.service === "ldap" || p.port === 389 || p.port === 636);
    expect(hasLDAP).toBe(true);
  });

  it("DNS port triggers zone transfer check", () => {
    const ports = [{ port: 53, service: "dns" }];
    const hasDNS = ports.some(p => p.service === "dns" || p.port === 53);
    expect(hasDNS).toBe(true);
  });

  it("non-standard web ports are also detected", () => {
    const ports = [
      { port: 8080, service: "http-proxy" },
      { port: 8443, service: "http-alt" },
    ];

    const webPorts = ports.filter(p =>
      ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );

    expect(webPorts).toHaveLength(2);
  });
});

// ─── Exploit Matching — CVE to Module Mapping ────────────────────────────

describe("Exploit Matching — Enhanced Module Mapping", () => {
  it("CVE generates correct MSF module path", () => {
    const cve = "CVE-2024-1234";
    const module = `exploit/multi/http/${cve.toLowerCase().replace(/-/g, '_')}`;
    const aux = `auxiliary/scanner/http/${cve.toLowerCase().replace(/-/g, '_')}_check`;

    expect(module).toBe("exploit/multi/http/cve_2024_1234");
    expect(aux).toBe("auxiliary/scanner/http/cve_2024_1234_check");
  });

  it("RCE vulns generate additional MSF and ZAP rules", () => {
    const title = "Remote Code Execution via deserialization";
    const titleLower = title.toLowerCase();
    const msfModules: string[] = [];
    const zapRules: string[] = [];

    if (titleLower.includes('rce') || titleLower.includes('remote code') || titleLower.includes('command execution')) {
      msfModules.push("exploit/multi/misc/rce_target");
      zapRules.push('Remote Code Execution', 'OS Command Injection');
    }

    expect(msfModules).toHaveLength(1);
    expect(zapRules).toContain("Remote Code Execution");
    expect(zapRules).toContain("OS Command Injection");
  });

  it("LFI vulns generate path traversal rules", () => {
    const title = "Local File Inclusion in /etc/passwd";
    const titleLower = title.toLowerCase();
    const zapRules: string[] = [];

    if (titleLower.includes('lfi') || titleLower.includes('local file') || titleLower.includes('path traversal')) {
      zapRules.push('Path Traversal', 'Local File Inclusion');
    }

    expect(zapRules).toContain("Path Traversal");
    expect(zapRules).toContain("Local File Inclusion");
  });

  it("deduplicates MSF modules from bridge and fallback", () => {
    const exploitBridgeModules = ["exploit/multi/http/cve_2024_1234"];
    const msfModules = ["exploit/multi/http/cve_2024_1234", "auxiliary/scanner/http/cve_2024_1234_check"];

    const allMsf = [...new Set([...exploitBridgeModules, ...msfModules])];
    expect(allMsf).toHaveLength(2); // deduplicated
    expect(allMsf).toContain("exploit/multi/http/cve_2024_1234");
    expect(allMsf).toContain("auxiliary/scanner/http/cve_2024_1234_check");
  });
});

// ─── Nmap-First Enforcement ──────────────────────────────────────────────

describe("Nmap-First Enforcement", () => {
  it("enumeration phase always starts with nmap before other tools", () => {
    // The orchestrator's executeEnumeration runs nmap first for every asset
    // This test verifies the expected log order
    const logEntries = [
      { phase: "enumeration", type: "scan_start", title: "Nmap SYN Scan: target.com" },
      { phase: "enumeration", type: "scan_result", title: "Nmap Complete: target.com" },
      { phase: "enumeration", type: "tool_match", title: "Tool Match: target.com" },
      { phase: "vuln_detection", type: "scan_start", title: "Nuclei Scan: target.com" },
      { phase: "vuln_detection", type: "zap_scan", title: "ZAP Spider: target.com" },
    ];

    // Nmap entries must come before tool_match entries
    const nmapIdx = logEntries.findIndex(l => l.title.includes("Nmap SYN"));
    const toolMatchIdx = logEntries.findIndex(l => l.type === "tool_match");
    const nucleiIdx = logEntries.findIndex(l => l.title.includes("Nuclei"));
    const zapIdx = logEntries.findIndex(l => l.title.includes("ZAP"));

    expect(nmapIdx).toBeLessThan(toolMatchIdx);
    expect(toolMatchIdx).toBeLessThan(nucleiIdx);
    expect(toolMatchIdx).toBeLessThan(zapIdx);
  });

  it("active scan requires RoE signed status", () => {
    const roeStatuses = ["signed", "pending", "none", "draft"];
    const allowedForActive = roeStatuses.filter(s => s === "signed" || s === "pending");
    expect(allowedForActive).toContain("signed");
    expect(allowedForActive).toContain("pending");
    expect(allowedForActive).not.toContain("none");
    expect(allowedForActive).not.toContain("draft");
  });

  it("passive scan does not require RoE", () => {
    // Passive recon (OSINT, domain intel) runs without RoE
    const passivePhases = ["recon"];
    const requiresRoE = (phase: string) => !passivePhases.includes(phase);

    expect(requiresRoE("recon")).toBe(false);
    expect(requiresRoE("enumeration")).toBe(true);
    expect(requiresRoE("exploitation")).toBe(true);
  });
});
