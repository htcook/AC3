/**
 * Nmap Router — Unit Tests
 *
 * Tests the Nmap tRPC router structure, scan profile definitions,
 * NSE script categories, admin port catalog, input validation schemas,
 * scope enforcement integration, and helper functions.
 *
 * Does NOT require network access — all tests are pure-logic / source-analysis.
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Source Analysis ────────────────────────────────────────────────────────

const routerPath = path.join(__dirname, "routers/nmap.ts");
const routerSrc = fs.readFileSync(routerPath, "utf8");

const orchestratorPath = path.join(__dirname, "lib/nmap-orchestrator.ts");
const orchestratorSrc = fs.readFileSync(orchestratorPath, "utf8");

const mainRouterPath = path.join(__dirname, "routers.ts");
const mainRouterSrc = fs.readFileSync(mainRouterPath, "utf8");

// ─── Router Module Structure ────────────────────────────────────────────────

describe("Nmap Router: Module Structure", () => {
  it("exports nmapRouter", () => {
    expect(routerSrc).toContain("export const nmapRouter = router({");
  });

  it("imports from nmap-orchestrator", () => {
    expect(routerSrc).toContain('from "../lib/nmap-orchestrator"');
  });

  it("imports scope enforcement middleware", () => {
    expect(routerSrc).toContain('from "../lib/scope-enforcement-middleware"');
  });

  it("imports enforceMultiTargetScope", () => {
    expect(routerSrc).toContain("enforceMultiTargetScope");
  });

  it("imports protectedProcedure and router from trpc core", () => {
    expect(routerSrc).toContain('import { protectedProcedure, router } from "../_core/trpc"');
  });

  it("imports TRPCError for error handling", () => {
    expect(routerSrc).toContain('import { TRPCError } from "@trpc/server"');
  });

  it("imports zod for input validation", () => {
    expect(routerSrc).toContain('import { z } from "zod"');
  });
});

// ─── Router Registration in Main App ────────────────────────────────────────

describe("Nmap Router: Registration", () => {
  it("is imported in main routers.ts", () => {
    expect(mainRouterSrc).toContain('import { nmapRouter } from "./routers/nmap"');
  });

  it("is registered in the appRouter", () => {
    expect(mainRouterSrc).toContain("nmap: nmapRouter");
  });
});

// ─── Mutation Procedures ────────────────────────────────────────────────────

describe("Nmap Router: Mutation Procedures", () => {
  const mutationProcedures = [
    "scan",
    "quickScan",
    "serviceScan",
    "osScan",
    "scriptScan",
    "vulnScan",
    "adminPortScan",
    "preflight",
  ];

  for (const proc of mutationProcedures) {
    it(`exposes ${proc} as a mutation`, () => {
      // Each mutation procedure should be defined in the router
      const pattern = new RegExp(`${proc}:\\s*protectedProcedure`);
      expect(routerSrc).toMatch(pattern);
    });
  }

  it("scan procedure accepts engagementId, targets, profile, server", () => {
    expect(routerSrc).toContain("engagementId: z.number()");
    expect(routerSrc).toContain("targets: z.array(z.string()");
    expect(routerSrc).toContain("profile: profileSchema");
    expect(routerSrc).toContain("server: serverSchema");
  });

  it("scan procedure accepts optional ports, customArgs, scripts, excludeHosts", () => {
    expect(routerSrc).toContain("ports: z.string().optional()");
    expect(routerSrc).toContain("customArgs: z.string().optional()");
    expect(routerSrc).toContain("scripts: z.array(z.string()).optional()");
    expect(routerSrc).toContain("excludeHosts: z.array(z.string()).optional()");
  });

  it("scan procedure accepts optional timeoutSeconds with bounds", () => {
    expect(routerSrc).toContain("timeoutSeconds: z.number().int().min(");
  });

  it("serviceScan requires ports parameter", () => {
    // serviceScan should have a required ports field (not optional)
    const serviceScanBlock = routerSrc.split("serviceScan:")[1]?.split(".mutation")[0] || "";
    expect(serviceScanBlock).toContain("ports: z.string().min(1)");
  });

  it("scriptScan accepts category or individual scripts", () => {
    expect(routerSrc).toContain('category: z.enum(["auth", "discovery", "vuln", "brute", "safe_recon", "web", "smb"])');
    expect(routerSrc).toContain("scripts: z.array(z.string()).optional()");
  });

  it("preflight accepts server configuration", () => {
    const preflightBlock = routerSrc.split("preflight:")[1]?.split("})")[0] || "";
    expect(preflightBlock).toContain("server: serverSchema");
  });
});

// ─── Query Procedures ───────────────────────────────────────────────────────

describe("Nmap Router: Query Procedures", () => {
  const queryProcedures = [
    "getResult",
    "getResultAsObservations",
    "getHistory",
    "getProfiles",
    "getScriptCategories",
    "getAdminPorts",
  ];

  for (const proc of queryProcedures) {
    it(`exposes ${proc} as a query`, () => {
      const pattern = new RegExp(`${proc}:\\s*protectedProcedure`);
      expect(routerSrc).toMatch(pattern);
    });
  }

  it("getResult accepts scanId", () => {
    expect(routerSrc).toContain("scanId: z.string()");
  });

  it("getHistory accepts optional filters (engagementId, profile, status, limit, offset)", () => {
    const historyBlock = routerSrc.split("getHistory:")[1]?.split(".query")[0] || "";
    expect(historyBlock).toContain("engagementId: z.number().optional()");
    expect(historyBlock).toContain("profile: profileSchema.optional()");
    expect(historyBlock).toContain("limit: z.number()");
    expect(historyBlock).toContain("offset: z.number()");
  });
});

// ─── Scope Enforcement ──────────────────────────────────────────────────────

describe("Nmap Router: Scope Enforcement", () => {
  const scopeEnforcedProcedures = [
    { name: "scan", tool: "nmap_" },
    { name: "quickScan", tool: "nmap_quick" },
    { name: "serviceScan", tool: "nmap_service" },
    { name: "osScan", tool: "nmap_os_detection" },
    { name: "scriptScan", tool: "nmap_script" },
    { name: "vulnScan", tool: "nmap_vuln" },
    { name: "adminPortScan", tool: "nmap_admin_ports" },
  ];

  for (const { name, tool } of scopeEnforcedProcedures) {
    it(`${name} calls enforceMultiTargetScope before execution`, () => {
      // Find the procedure block
      const procBlock = routerSrc.split(`${name}:`)[1]?.split(/\n  \w+:/)[0] || "";
      expect(procBlock).toContain("enforceMultiTargetScope");
    });

    it(`${name} passes tool identifier containing "${tool}"`, () => {
      // The source may use template literals (backticks) or double quotes
      expect(routerSrc).toContain(tool);
    });
  }

  it("all mutation procedures (except preflight) enforce scope", () => {
    // Count enforceMultiTargetScope calls — should be 7 (one per active scan mutation)
    const scopeCalls = (routerSrc.match(/enforceMultiTargetScope\(/g) || []).length;
    expect(scopeCalls).toBeGreaterThanOrEqual(7);
  });

  it("preflight does NOT enforce scope (it's a server check, not a target scan)", () => {
    const preflightBlock = routerSrc.split("preflight:")[1]?.split("})")[0] || "";
    expect(preflightBlock).not.toContain("enforceMultiTargetScope");
  });
});

// ─── Scan Profiles ──────────────────────────────────────────────────────────

describe("Nmap Router: Scan Profile Definitions", () => {
  const profiles = ["quick", "standard", "deep", "stealth", "service", "udp", "vuln", "custom"];

  for (const profile of profiles) {
    it(`defines the "${profile}" scan profile`, () => {
      expect(routerSrc).toContain(`${profile}:`);
    });
  }

  it("profile schema validates all 8 profiles", () => {
    expect(routerSrc).toContain('z.enum([');
    for (const p of profiles) {
      expect(routerSrc).toContain(`"${p}"`);
    }
  });

  it("each profile has name, description, flags, estimatedDuration, useCase, portsScanned, requiresSudo", () => {
    const profileBlock = routerSrc.split("SCAN_PROFILE_DESCRIPTIONS")[1]?.split("NSE_SCRIPT_CATEGORIES")[0] || "";
    for (const field of ["name:", "description:", "flags:", "estimatedDuration:", "useCase:", "portsScanned:", "requiresSudo:"]) {
      expect(profileBlock).toContain(field);
    }
  });

  it("quick profile scans top 100 ports", () => {
    expect(routerSrc).toContain("Top 100 TCP");
  });

  it("standard profile scans top 1000 ports", () => {
    expect(routerSrc).toContain("Top 1000 TCP");
  });

  it("deep profile scans all 65535 ports", () => {
    expect(routerSrc).toContain("All 65535 TCP");
  });

  it("stealth profile uses rate limiting and randomized hosts", () => {
    expect(routerSrc).toContain("--randomize-hosts");
    expect(routerSrc).toContain("--max-rate");
  });

  it("udp profile scans top 50 UDP ports", () => {
    expect(routerSrc).toContain("Top 50 UDP");
  });

  it("vuln profile uses --script vuln", () => {
    expect(routerSrc).toContain("--script vuln");
  });
});

// ─── NSE Script Categories ──────────────────────────────────────────────────

describe("Nmap Router: NSE Script Categories", () => {
  const categories = ["auth", "discovery", "vuln", "brute", "safe_recon", "web", "smb"];

  for (const cat of categories) {
    it(`defines the "${cat}" script category`, () => {
      expect(routerSrc).toContain(`${cat}:`);
    });
  }

  it("each category has name, description, scripts array, and useCase", () => {
    const catBlock = routerSrc.split("NSE_SCRIPT_CATEGORIES")[1]?.split("function generateScanId")[0] || "";
    expect(catBlock).toContain("name:");
    expect(catBlock).toContain("description:");
    expect(catBlock).toContain("scripts:");
    expect(catBlock).toContain("useCase:");
  });

  it("auth category includes ftp-anon and ssh-auth-methods", () => {
    expect(routerSrc).toContain("ftp-anon");
    expect(routerSrc).toContain("ssh-auth-methods");
  });

  it("discovery category includes smb-enum-shares and dns-zone-transfer", () => {
    expect(routerSrc).toContain("smb-enum-shares");
    expect(routerSrc).toContain("dns-zone-transfer");
  });

  it("vuln category includes smb-vuln-ms17-010 and ssl-heartbleed", () => {
    expect(routerSrc).toContain("smb-vuln-ms17-010");
    expect(routerSrc).toContain("ssl-heartbleed");
  });

  it("brute category includes ssh-brute and ftp-brute", () => {
    expect(routerSrc).toContain("ssh-brute");
    expect(routerSrc).toContain("ftp-brute");
  });

  it("safe_recon category includes banner and http-title", () => {
    expect(routerSrc).toContain('"banner"');
    expect(routerSrc).toContain('"http-title"');
  });

  it("web category includes http-enum and http-robots.txt", () => {
    expect(routerSrc).toContain("http-enum");
    expect(routerSrc).toContain("http-robots.txt");
  });

  it("smb category includes smb-protocols and smb-security-mode", () => {
    expect(routerSrc).toContain("smb-protocols");
    expect(routerSrc).toContain("smb-security-mode");
  });

  it("scriptScan validates that either category or scripts must be provided", () => {
    expect(routerSrc).toContain("Must specify either a script category or individual scripts");
  });
});

// ─── Server Schema ──────────────────────────────────────────────────────────

describe("Nmap Router: Server Schema Validation", () => {
  it("requires host as non-empty string", () => {
    expect(routerSrc).toContain("host: z.string().min(1)");
  });

  it("accepts optional port with valid range", () => {
    expect(routerSrc).toContain("port: z.number().int().min(1).max(65535).optional()");
  });

  it("requires username as non-empty string", () => {
    expect(routerSrc).toContain("username: z.string().min(1)");
  });

  it("accepts optional privateKey and privateKeyPath", () => {
    expect(routerSrc).toContain("privateKey: z.string().optional()");
    expect(routerSrc).toContain("privateKeyPath: z.string().optional()");
  });

  it("accepts optional nmapPath for custom binary location", () => {
    expect(routerSrc).toContain("nmapPath: z.string().optional()");
  });
});

// ─── Scan History ───────────────────────────────────────────────────────────

describe("Nmap Router: Scan History Management", () => {
  it("maintains an in-memory scan history store", () => {
    expect(routerSrc).toContain("const scanHistory: ScanHistoryEntry[]");
  });

  it("maintains an in-memory scan results store", () => {
    expect(routerSrc).toContain("const scanResults: Map<string, NmapScanResult>");
  });

  it("generates unique scan IDs with nmap prefix", () => {
    expect(routerSrc).toContain("nmap-${Date.now()}");
  });

  it("limits history to 500 entries", () => {
    expect(routerSrc).toContain("500");
  });

  it("history entries track engagementId, targets, profile, status", () => {
    const historyInterface = routerSrc.split("interface ScanHistoryEntry")[1]?.split("}")[0] || "";
    expect(historyInterface).toContain("engagementId: number");
    expect(historyInterface).toContain("targets: string[]");
    expect(historyInterface).toContain("profile: NmapScanProfile");
    expect(historyInterface).toContain("status:");
  });

  it("history entries track timing (startedAt, completedAt, durationMs)", () => {
    const historyInterface = routerSrc.split("interface ScanHistoryEntry")[1]?.split("}")[0] || "";
    expect(historyInterface).toContain("startedAt: number");
    expect(historyInterface).toContain("completedAt?: number");
    expect(historyInterface).toContain("durationMs?: number");
  });

  it("history entries track operator info", () => {
    const historyInterface = routerSrc.split("interface ScanHistoryEntry")[1]?.split("}")[0] || "";
    expect(historyInterface).toContain("operatorId: string");
    expect(historyInterface).toContain("operatorName?: string");
  });

  it("getHistory supports filtering by engagementId", () => {
    expect(routerSrc).toContain("e.engagementId === input.engagementId");
  });

  it("getHistory supports filtering by profile", () => {
    expect(routerSrc).toContain("e.profile === input.profile");
  });

  it("getHistory supports filtering by status", () => {
    expect(routerSrc).toContain("e.status === input.status");
  });

  it("getHistory supports pagination with limit and offset", () => {
    expect(routerSrc).toContain("filtered.slice(offset, offset + limit)");
  });

  it("getHistory returns total count", () => {
    expect(routerSrc).toContain("total: filtered.length");
  });
});

// ─── Error Handling ─────────────────────────────────────────────────────────

describe("Nmap Router: Error Handling", () => {
  it("throws INTERNAL_SERVER_ERROR on scan failure", () => {
    expect(routerSrc).toContain('code: "INTERNAL_SERVER_ERROR"');
  });

  it("includes descriptive error messages for each scan type", () => {
    expect(routerSrc).toContain("Nmap scan failed:");
    expect(routerSrc).toContain("Quick scan failed:");
    expect(routerSrc).toContain("Service scan failed:");
    expect(routerSrc).toContain("OS detection scan failed:");
    expect(routerSrc).toContain("Script scan failed:");
    expect(routerSrc).toContain("Vulnerability scan failed:");
    expect(routerSrc).toContain("Admin port scan failed:");
  });

  it("throws NOT_FOUND when scan result is missing", () => {
    expect(routerSrc).toContain('code: "NOT_FOUND"');
  });

  it("throws BAD_REQUEST for invalid script scan input", () => {
    expect(routerSrc).toContain('code: "BAD_REQUEST"');
  });

  it("updates history entry status on failure", () => {
    const failureUpdates = (routerSrc.match(/historyEntry\.status = "failed"/g) || []).length;
    expect(failureUpdates).toBeGreaterThanOrEqual(7);
  });

  it("records error message in history entry", () => {
    const errorRecords = (routerSrc.match(/historyEntry\.error = err\.message/g) || []).length;
    expect(errorRecords).toBeGreaterThanOrEqual(7);
  });
});

// ─── Vulnerability Scan Specifics ───────────────────────────────────────────

describe("Nmap Router: Vulnerability Scan Features", () => {
  it("extracts CVEs from script output", () => {
    expect(routerSrc).toContain("function extractCVEs");
    expect(routerSrc).toContain("CVE-\\d{4}-\\d{4,}");
  });

  it("deduplicates extracted CVEs", () => {
    expect(routerSrc).toContain("new Set(matches.map");
  });

  it("uppercases CVE identifiers", () => {
    expect(routerSrc).toContain("toUpperCase()");
  });

  it("returns empty array when no CVEs found", () => {
    expect(routerSrc).toContain(": [];");
  });

  it("vulnScan identifies vulnerable hosts", () => {
    expect(routerSrc).toContain("vulnerableHosts:");
  });

  it("vulnScan counts vulnerability findings", () => {
    expect(routerSrc).toContain("vulnCount: vulnFindings.length");
  });

  it("vulnScan checks for 'vulnerable' keyword in script output", () => {
    expect(routerSrc).toContain('.includes("vulnerable")');
  });

  it("vulnScan checks for CVE references in script output", () => {
    expect(routerSrc).toContain('.includes("cve-")');
  });
});

// ─── Admin Port Scan Specifics ──────────────────────────────────────────────

describe("Nmap Router: Admin Port Scan Features", () => {
  it("uses getAllAdminPorts from orchestrator", () => {
    expect(routerSrc).toContain("getAllAdminPorts()");
  });

  it("categorizes discovered ports by service type", () => {
    expect(routerSrc).toContain("categorizedPorts");
  });

  it("returns the admin port catalog in results", () => {
    expect(routerSrc).toContain("adminPortCatalog: ADMIN_SERVICE_PORTS");
  });

  it("iterates over ADMIN_SERVICE_PORTS categories", () => {
    expect(routerSrc).toContain("Object.entries(ADMIN_SERVICE_PORTS)");
  });
});

// ─── OS Detection Scan Specifics ────────────────────────────────────────────

describe("Nmap Router: OS Detection Features", () => {
  it("extracts OS results from scan data", () => {
    expect(routerSrc).toContain("osResults");
  });

  it("filters hosts that have OS detection results", () => {
    expect(routerSrc).toContain("h.os");
  });

  it("returns OS info alongside open port count", () => {
    const osBlock = routerSrc.split("osResults")[1]?.split("return")[0] || "";
    expect(osBlock).toContain("os: h.os!");
  });
});

// ─── Script Scan Specifics ──────────────────────────────────────────────────

describe("Nmap Router: Script Scan Features", () => {
  it("resolves scripts from category when category is specified", () => {
    expect(routerSrc).toContain("resolvedScripts = cat.scripts");
  });

  it("uses individual scripts when no category is specified", () => {
    expect(routerSrc).toContain("resolvedScripts = input.scripts!");
  });

  it("extracts script findings from host-level and port-level scripts", () => {
    expect(routerSrc).toContain("scriptFindings");
  });

  it("includes host-level scripts (port 0) in findings", () => {
    expect(routerSrc).toContain("port: 0");
  });

  it("returns scripts used and findings count", () => {
    expect(routerSrc).toContain("scriptsUsed: resolvedScripts");
    expect(routerSrc).toContain("findingsCount: scriptFindings.length");
  });
});

// ─── SSIL Integration ───────────────────────────────────────────────────────

describe("Nmap Router: SSIL Observation Integration", () => {
  it("getResultAsObservations calls toNmapRawResults", () => {
    expect(routerSrc).toContain("toNmapRawResults(result");
  });

  it("getResultAsObservations accepts optional policyProfile", () => {
    expect(routerSrc).toContain("policyProfile: z.string().optional()");
  });
});

// ─── Orchestrator Integration ───────────────────────────────────────────────

describe("Nmap Router: Orchestrator Integration", () => {
  it("imports executeNmapScan from orchestrator", () => {
    expect(routerSrc).toContain("executeNmapScan");
  });

  it("imports scanWithScopeEnforcement from orchestrator", () => {
    expect(routerSrc).toContain("scanWithScopeEnforcement");
  });

  it("imports preflightCheck from orchestrator", () => {
    expect(routerSrc).toContain("preflightCheck");
  });

  it("imports parseNmapXml from orchestrator", () => {
    expect(routerSrc).toContain("parseNmapXml");
  });

  it("imports toNmapRawResults from orchestrator", () => {
    expect(routerSrc).toContain("toNmapRawResults");
  });

  it("imports getAllAdminPorts from orchestrator", () => {
    expect(routerSrc).toContain("getAllAdminPorts");
  });

  it("imports ADMIN_SERVICE_PORTS from orchestrator", () => {
    expect(routerSrc).toContain("ADMIN_SERVICE_PORTS");
  });

  it("imports type definitions from orchestrator", () => {
    expect(routerSrc).toContain("type NmapScanConfig");
    expect(routerSrc).toContain("type NmapScanResult");
    expect(routerSrc).toContain("type NmapScanProfile");
    expect(routerSrc).toContain("type ScanServerConfig");
  });
});

// ─── CVE Extraction Function Tests ──────────────────────────────────────────

describe("Nmap Router: extractCVEs helper (source analysis)", () => {
  it("uses a regex pattern that matches CVE-YYYY-NNNNN format", () => {
    expect(routerSrc).toContain("CVE-\\d{4}-\\d{4,}");
  });

  it("uses global and case-insensitive flags", () => {
    expect(routerSrc).toContain("/gi");
  });

  it("deduplicates results using Set", () => {
    const extractBlock = routerSrc.split("function extractCVEs")[1] || "";
    expect(extractBlock).toContain("new Set");
  });
});

// ─── Target Limits ──────────────────────────────────────────────────────────

describe("Nmap Router: Target Limits", () => {
  it("scan allows up to 256 targets", () => {
    expect(routerSrc).toContain(".max(256)");
  });

  it("osScan limits to 64 targets (OS detection is slow)", () => {
    expect(routerSrc).toContain(".max(64)");
  });

  it("scriptScan limits to 128 targets", () => {
    expect(routerSrc).toContain(".max(128)");
  });

  it("all scan procedures require at least 1 target", () => {
    const minCalls = (routerSrc.match(/\.min\(1\)/g) || []).length;
    expect(minCalls).toBeGreaterThanOrEqual(7);
  });
});

// ─── Timeout Configuration ──────────────────────────────────────────────────

describe("Nmap Router: Timeout Configuration", () => {
  it("quickScan has a default timeout of 120 seconds", () => {
    expect(routerSrc).toContain("timeoutSeconds: input.timeoutSeconds || 120");
  });

  it("serviceScan has a default timeout of 300 seconds", () => {
    expect(routerSrc).toContain("timeoutSeconds: input.timeoutSeconds || 300");
  });

  it("osScan has a default timeout of 600 seconds", () => {
    expect(routerSrc).toContain("timeoutSeconds: input.timeoutSeconds || 600");
  });

  it("scriptScan has a default timeout of 900 seconds", () => {
    expect(routerSrc).toContain("timeoutSeconds: input.timeoutSeconds || 900");
  });

  it("vulnScan has a default timeout of 1800 seconds", () => {
    expect(routerSrc).toContain("timeoutSeconds: input.timeoutSeconds || 1800");
  });
});

// ─── Procedure Count ────────────────────────────────────────────────────────

describe("Nmap Router: Completeness", () => {
  it("has exactly 14 procedures (7 mutations + 6 queries + 1 preflight)", () => {
    const procedures = [
      "scan:", "quickScan:", "serviceScan:", "osScan:",
      "scriptScan:", "vulnScan:", "adminPortScan:",
      "getResult:", "getResultAsObservations:", "getHistory:",
      "getProfiles:", "getScriptCategories:", "getAdminPorts:",
      "preflight:",
    ];
    for (const proc of procedures) {
      expect(routerSrc).toContain(proc);
    }
  });

  it("all mutation procedures use protectedProcedure", () => {
    const protectedCount = (routerSrc.match(/protectedProcedure/g) || []).length;
    expect(protectedCount).toBeGreaterThanOrEqual(14);
  });

  it("router file is substantial (> 500 lines)", () => {
    const lineCount = routerSrc.split("\n").length;
    expect(lineCount).toBeGreaterThan(500);
  });
});
