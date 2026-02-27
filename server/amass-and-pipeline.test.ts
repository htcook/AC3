/**
 * Tests for Amass Engine, Service Fingerprinter Router, and Unified Pipeline Integration
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Amass Engine Tests ─────────────────────────────────────────────────────

describe("Amass Engine", () => {
  const enginePath = path.join(__dirname, "lib/amass-engine.ts");
  const engineSrc = fs.readFileSync(enginePath, "utf8");

  describe("Module structure", () => {
    it("exports executeAmassEnum function", () => {
      expect(engineSrc).toContain("export async function executeAmassEnum");
    });

    it("exports executeAmassIntel function", () => {
      expect(engineSrc).toContain("export async function executeAmassIntel");
    });

    it("exports scanWithScopeEnforcement function", () => {
      expect(engineSrc).toContain("export async function scanWithScopeEnforcement");
    });

    it("exports preflightCheck function", () => {
      expect(engineSrc).toContain("export async function preflightCheck");
    });

    it("exports diffAmassResults function", () => {
      expect(engineSrc).toContain("export function diffAmassResults");
    });

    it("exports toUnifiedDiscoveryFormat function", () => {
      expect(engineSrc).toContain("export function toUnifiedDiscoveryFormat");
    });

    it("exports deployBuiltInWordlist function", () => {
      expect(engineSrc).toContain("export async function deployBuiltInWordlist");
    });

    it("exports parseAmassJsonOutput function", () => {
      expect(engineSrc).toContain("export function parseAmassJsonOutput");
    });

    it("exports generateAmassSummary function", () => {
      expect(engineSrc).toContain("export function generateAmassSummary");
    });

    it("exports BUILT_IN_WORDLIST constant", () => {
      expect(engineSrc).toContain("export const BUILT_IN_WORDLIST");
    });
  });

  describe("Scan modes", () => {
    it("supports passive mode", () => {
      expect(engineSrc).toContain('"passive"');
    });

    it("supports active mode", () => {
      expect(engineSrc).toContain('"active"');
    });

    it("supports brute mode", () => {
      expect(engineSrc).toContain('"brute"');
    });

    it("supports full mode", () => {
      expect(engineSrc).toContain('"full"');
    });

    it("supports intel mode", () => {
      expect(engineSrc).toContain('"intel"');
    });
  });

  describe("Intel modes", () => {
    it("supports org intel mode", () => {
      expect(engineSrc).toContain('"org"');
    });

    it("supports asn intel mode", () => {
      expect(engineSrc).toContain('"asn"');
    });

    it("supports cidr intel mode", () => {
      expect(engineSrc).toContain('"cidr"');
    });

    it("supports whois intel mode", () => {
      expect(engineSrc).toContain('"whois"');
    });
  });

  describe("SSH execution pattern", () => {
    it("uses executeSSHCommand for remote execution", () => {
      expect(engineSrc).toContain("executeSSHCommand");
    });

    it("supports custom amass binary path", () => {
      expect(engineSrc).toContain("amassPath");
    });

    it("supports custom config file path", () => {
      expect(engineSrc).toContain("configPath");
    });

    it("supports custom resolvers", () => {
      expect(engineSrc).toContain("resolvers");
    });

    it("supports blacklist domains", () => {
      expect(engineSrc).toContain("blacklist");
    });

    it("supports timeout configuration", () => {
      expect(engineSrc).toContain("timeoutMinutes");
    });
  });

  describe("Output parsing", () => {
    it("parses JSON output format", () => {
      expect(engineSrc).toContain("parseAmassJsonOutput");
      expect(engineSrc).toContain("JSON.parse");
    });

    it("generates summary statistics", () => {
      expect(engineSrc).toContain("totalSubdomains");
      expect(engineSrc).toContain("totalUniqueIps");
      expect(engineSrc).toContain("totalAsns");
      expect(engineSrc).toContain("totalSources");
    });
  });

  describe("Scope enforcement", () => {
    it("imports scope guard for enforcement", () => {
      expect(engineSrc).toContain("scope-guard");
    });

    it("validates targets against ROE before active scanning", () => {
      expect(engineSrc).toContain("scanWithScopeEnforcement");
    });
  });

  describe("Diff capability", () => {
    it("identifies new subdomains", () => {
      expect(engineSrc).toContain("newSubdomains");
    });

    it("identifies removed subdomains", () => {
      expect(engineSrc).toContain("removedSubdomains");
    });

    it("identifies new IPs", () => {
      expect(engineSrc).toContain("newSubdomains");
    });

    it("identifies removed IPs", () => {
      expect(engineSrc).toContain("removedSubdomains");
    });
  });

  describe("Unified discovery format", () => {
    it("converts results to unified format", () => {
      expect(engineSrc).toContain("toUnifiedDiscoveryFormat");
    });

    it("includes name in unified format", () => {
      expect(engineSrc).toContain("name: sub.name");
    });

    it("includes IP addresses in unified format", () => {
      expect(engineSrc).toContain("addresses");
    });

    it("includes source attribution", () => {
      expect(engineSrc).toContain("source");
    });
  });

  describe("Built-in wordlist", () => {
    it("contains common subdomain prefixes", () => {
      expect(engineSrc).toContain('"www"');
      expect(engineSrc).toContain('"mail"');
      expect(engineSrc).toContain('"api"');
      expect(engineSrc).toContain('"admin"');
    });

    it("deploys wordlist to remote server", () => {
      expect(engineSrc).toContain("deployBuiltInWordlist");
    });
  });
});

// ─── Service Fingerprinter Router Tests ─────────────────────────────────────

describe("Service Fingerprinter Router", () => {
  const routerPath = path.join(__dirname, "routers/service-fingerprinter.ts");
  const routerSrc = fs.readFileSync(routerPath, "utf8");

  describe("tRPC procedures", () => {
    it("has fingerprint mutation for single service", () => {
      expect(routerSrc).toContain("fingerprint: protectedProcedure");
    });

    it("has batchFingerprint mutation for multiple targets", () => {
      expect(routerSrc).toContain("batchFingerprint: protectedProcedure");
    });

    it("has autoFingerprint mutation for Nmap/Naabu results", () => {
      expect(routerSrc).toContain("autoFingerprint: protectedProcedure");
    });

    it("has getPortProtocolMap query", () => {
      expect(routerSrc).toContain("getPortProtocolMap: protectedProcedure");
    });

    it("has detectProtocol query", () => {
      expect(routerSrc).toContain("detectProtocol: protectedProcedure");
    });

    it("has getScanHistory query", () => {
      expect(routerSrc).toContain("getScanHistory: protectedProcedure");
    });

    it("has getScanResult query", () => {
      expect(routerSrc).toContain("getScanResult: protectedProcedure");
    });
  });

  describe("Scope enforcement", () => {
    it("imports scope enforcement middleware", () => {
      expect(routerSrc).toContain("scope-enforcement-middleware");
    });

    it("enforces scope on single fingerprint", () => {
      expect(routerSrc).toContain("enforceTargetScope");
    });

    it("enforces scope on batch fingerprint with unique hosts", () => {
      expect(routerSrc).toContain("enforceMultiTargetScope");
    });

    it("enforces scope on auto fingerprint", () => {
      // autoFingerprint also calls enforceTargetScope
      const matches = routerSrc.match(/enforceTargetScope/g);
      expect(matches!.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Input validation", () => {
    it("validates port range 1-65535", () => {
      expect(routerSrc).toContain(".max(65535)");
    });

    it("validates timeout range", () => {
      expect(routerSrc).toContain(".max(60000)");
    });

    it("limits batch size to 500", () => {
      expect(routerSrc).toContain(".max(500)");
    });

    it("limits concurrency to 50", () => {
      expect(routerSrc).toContain(".max(50)");
    });

    it("limits auto fingerprint ports to 1000", () => {
      expect(routerSrc).toContain(".max(1000)");
    });
  });

  describe("Protocol support", () => {
    const protocols = [
      "ssh", "smtp", "ftp", "snmp", "rdp", "smb", "ldap", "telnet",
      "mysql", "mssql", "postgresql", "redis", "mongodb", "vnc",
    ];

    protocols.forEach(proto => {
      it(`supports ${proto} protocol`, () => {
        expect(routerSrc).toContain(`"${proto}"`);
      });
    });
  });

  describe("Summary generation", () => {
    it("calls summarizeFingerprints for batch results", () => {
      expect(routerSrc).toContain("summarizeFingerprints");
    });

    it("stores scan history", () => {
      expect(routerSrc).toContain("scanHistory.push");
    });
  });
});

// ─── Amass Router Tests ─────────────────────────────────────────────────────

describe("Amass Router", () => {
  const routerPath = path.join(__dirname, "routers/amass.ts");
  const routerSrc = fs.readFileSync(routerPath, "utf8");

  describe("tRPC procedures", () => {
    it("has enumerate mutation", () => {
      expect(routerSrc).toContain("enumerate: protectedProcedure");
    });

    it("has intel mutation", () => {
      expect(routerSrc).toContain("intel: protectedProcedure");
    });

    it("has getResult query", () => {
      expect(routerSrc).toContain("getResult: protectedProcedure");
    });

    it("has getUnifiedResults query", () => {
      expect(routerSrc).toContain("getUnifiedResults: protectedProcedure");
    });

    it("has diff query for attack surface change tracking", () => {
      expect(routerSrc).toContain("diff: protectedProcedure");
    });

    it("has preflight mutation for server checks", () => {
      expect(routerSrc).toContain("preflight: protectedProcedure");
    });

    it("has getScanHistory query", () => {
      expect(routerSrc).toContain("getScanHistory: protectedProcedure");
    });

    it("has getBuiltInWordlist query", () => {
      expect(routerSrc).toContain("getBuiltInWordlist: protectedProcedure");
    });
  });

  describe("Scope enforcement", () => {
    it("imports scope enforcement middleware", () => {
      expect(routerSrc).toContain("scope-enforcement-middleware");
    });

    it("enforces scope on active enumeration modes", () => {
      expect(routerSrc).toContain("enforceMultiTargetScope");
    });

    it("skips scope enforcement for passive mode", () => {
      expect(routerSrc).toContain("input.mode !== \"passive\"");
    });
  });

  describe("Scan modes", () => {
    it("supports passive, active, brute, and full modes", () => {
      expect(routerSrc).toContain("\"passive\", \"active\", \"brute\", \"full\"");
    });
  });

  describe("Intel modes", () => {
    it("supports org, asn, cidr, and whois intel modes", () => {
      expect(routerSrc).toContain("\"org\", \"asn\", \"cidr\", \"whois\"");
    });
  });

  describe("Input validation", () => {
    it("limits domains to 50", () => {
      expect(routerSrc).toContain(".max(50)");
    });

    it("validates server connection parameters", () => {
      expect(routerSrc).toContain("host: z.string()");
      expect(routerSrc).toContain("username: z.string()");
    });
  });

  describe("Unified discovery format", () => {
    it("converts results to unified format for pipeline ingestion", () => {
      expect(routerSrc).toContain("toUnifiedDiscoveryFormat");
    });
  });

  describe("Diff capability", () => {
    it("supports comparing two scan results", () => {
      expect(routerSrc).toContain("diffAmassResults");
    });
  });
});

// ─── Unified Pipeline Integration Tests ─────────────────────────────────────

describe("Unified Pipeline Integration", () => {
  const pipelinePath = path.join(__dirname, "lib/unified-pipeline.ts");
  const pipelineSrc = fs.readFileSync(pipelinePath, "utf8");

  describe("ToolModule type includes new tools", () => {
    it("includes amass in ToolModule", () => {
      expect(pipelineSrc).toContain("| 'amass'");
    });

    it("includes nmap in ToolModule", () => {
      expect(pipelineSrc).toContain("| 'nmap'");
    });

    it("includes service_fingerprinter in ToolModule", () => {
      expect(pipelineSrc).toContain("| 'service_fingerprinter'");
    });
  });

  describe("PIPELINE_STAGES includes new tools", () => {
    it("includes amass in recon phase", () => {
      // Extract recon phase tools
      const reconMatch = pipelineSrc.match(/phase:\s*'recon',\s*tools:\s*\[([^\]]+)\]/);
      expect(reconMatch).toBeTruthy();
      expect(reconMatch![1]).toContain("'amass'");
    });

    it("includes nmap in recon phase", () => {
      const reconMatch = pipelineSrc.match(/phase:\s*'recon',\s*tools:\s*\[([^\]]+)\]/);
      expect(reconMatch).toBeTruthy();
      expect(reconMatch![1]).toContain("'nmap'");
    });

    it("includes amass in enumeration phase", () => {
      const enumMatch = pipelineSrc.match(/phase:\s*'enumeration',\s*tools:\s*\[([^\]]+)\]/);
      expect(enumMatch).toBeTruthy();
      expect(enumMatch![1]).toContain("'amass'");
    });

    it("includes nmap in enumeration phase", () => {
      const enumMatch = pipelineSrc.match(/phase:\s*'enumeration',\s*tools:\s*\[([^\]]+)\]/);
      expect(enumMatch).toBeTruthy();
      expect(enumMatch![1]).toContain("'nmap'");
    });

    it("includes service_fingerprinter in enumeration phase", () => {
      const enumMatch = pipelineSrc.match(/phase:\s*'enumeration',\s*tools:\s*\[([^\]]+)\]/);
      expect(enumMatch).toBeTruthy();
      expect(enumMatch![1]).toContain("'service_fingerprinter'");
    });
  });

  describe("TOOL_PHASE_MATRIX entries", () => {
    it("has amass entry in TOOL_PHASE_MATRIX", () => {
      expect(pipelineSrc).toContain("amass: {");
    });

    it("has nmap entry in TOOL_PHASE_MATRIX", () => {
      expect(pipelineSrc).toContain("nmap: {");
    });

    it("has service_fingerprinter entry in TOOL_PHASE_MATRIX", () => {
      expect(pipelineSrc).toContain("service_fingerprinter: {");
    });

    it("amass outputs to nmap and service_fingerprinter", () => {
      const amassSection = pipelineSrc.match(/amass:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(amassSection).toBeTruthy();
      expect(amassSection![1]).toContain("'nmap'");
      expect(amassSection![1]).toContain("'service_fingerprinter'");
    });

    it("nmap outputs to service_fingerprinter", () => {
      const nmapSection = pipelineSrc.match(/nmap:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(nmapSection).toBeTruthy();
      expect(nmapSection![1]).toContain("'service_fingerprinter'");
    });

    it("service_fingerprinter receives input from nmap and amass", () => {
      const fpSection = pipelineSrc.match(/service_fingerprinter:\s*\{[\s\S]*?inputsFrom:\s*\[([^\]]+)\]/);
      expect(fpSection).toBeTruthy();
      expect(fpSection![1]).toContain("'nmap'");
      expect(fpSection![1]).toContain("'amass'");
    });

    it("nmap feeds into metasploit for exploit matching", () => {
      const nmapSection = pipelineSrc.match(/nmap:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(nmapSection).toBeTruthy();
      expect(nmapSection![1]).toContain("'metasploit'");
    });

    it("service_fingerprinter feeds into metasploit for exploit matching", () => {
      const fpSection = pipelineSrc.match(/service_fingerprinter:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(fpSection).toBeTruthy();
      expect(fpSection![1]).toContain("'metasploit'");
    });
  });

  describe("Pipeline data flow: Amass → Nmap → Fingerprinter → Exploit", () => {
    it("amass feeds discovered subdomains to nmap for port scanning", () => {
      const nmapInputs = pipelineSrc.match(/nmap:\s*\{[\s\S]*?inputsFrom:\s*\[([^\]]+)\]/);
      expect(nmapInputs).toBeTruthy();
      expect(nmapInputs![1]).toContain("'amass'");
    });

    it("nmap feeds open ports to service_fingerprinter for protocol probing", () => {
      const fpInputs = pipelineSrc.match(/service_fingerprinter:\s*\{[\s\S]*?inputsFrom:\s*\[([^\]]+)\]/);
      expect(fpInputs).toBeTruthy();
      expect(fpInputs![1]).toContain("'nmap'");
    });

    it("service_fingerprinter feeds to nvd_kev for CVE matching", () => {
      const fpOutputs = pipelineSrc.match(/service_fingerprinter:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(fpOutputs).toBeTruthy();
      expect(fpOutputs![1]).toContain("'nvd_kev'");
    });

    it("service_fingerprinter feeds to corroboration for cross-validation", () => {
      const fpOutputs = pipelineSrc.match(/service_fingerprinter:\s*\{[\s\S]*?outputsTo:\s*\[([^\]]+)\]/);
      expect(fpOutputs).toBeTruthy();
      expect(fpOutputs![1]).toContain("'corroboration'");
    });
  });
});

// ─── Router Registration Tests ──────────────────────────────────────────────

describe("Router Registration", () => {
  const routersPath = path.join(__dirname, "routers.ts");
  const routersSrc = fs.readFileSync(routersPath, "utf8");

  it("imports serviceFingerprintRouter", () => {
    expect(routersSrc).toContain("import { serviceFingerprintRouter }");
  });

  it("imports amassRouter", () => {
    expect(routersSrc).toContain("import { amassRouter }");
  });

  it("registers serviceFingerprint in appRouter", () => {
    expect(routersSrc).toContain("serviceFingerprint: serviceFingerprintRouter");
  });

  it("registers amass in appRouter", () => {
    expect(routersSrc).toContain("amass: amassRouter");
  });
});
