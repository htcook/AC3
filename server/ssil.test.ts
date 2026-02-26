import { describe, expect, it, beforeEach } from "vitest";
import {
  ScanPolicyEngine,
  getScanPolicyEngine,
  resetScanPolicyEngine,
} from "./lib/scan-policy-engine";
import {
  LLMGuardrails,
  getLLMGuardrails,
  resetLLMGuardrails,
} from "./lib/llm-guardrails";
import {
  adaptNmapResults,
  adaptNucleiResults,
  adaptZgrab2Results,
  adaptWebCrawlerResults,
  adaptDomainIntelResults,
  adaptVulnScanResults,
  deriveSignals,
  generateRiskCards,
  generateObservationId,
  fingerprintData,
  redactSensitiveHeaders,
  type NmapRawResult,
  type NucleiRawResult,
  type Zgrab2RawResult,
  type WebCrawlerRawResult,
  type DomainIntelRawResult,
  type VulnScanRawResult,
} from "./lib/observation-normalizer";

// ═══════════════════════════════════════════════════════════════════════════
// 1. SCAN POLICY ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("ScanPolicyEngine", () => {
  let engine: ScanPolicyEngine;

  beforeEach(() => {
    resetScanPolicyEngine();
    engine = getScanPolicyEngine();
  });

  it("initializes with strict_passive as default profile", () => {
    expect(engine.getActiveProfileId()).toBe("strict_passive");
  });

  it("lists all built-in profiles", () => {
    const profiles = engine.listProfiles();
    const ids = profiles.map((p) => p.id);
    expect(ids).toContain("strict_passive");
    expect(ids).toContain("balanced");
    expect(ids).toContain("aggressive_internal");
  });

  it("allows passive DNS scan in strict_passive mode", () => {
    const decision = engine.canExecute({
      scanner: "custom_dns",
      mode: "passive",
      asset: { host: "example.com", port: 53, protocol: "dns" },
    });
    expect(decision.allowed).toBe(true);
  });

  it("blocks active-aggressive scans in strict_passive mode", () => {
    const decision = engine.canExecute({
      scanner: "nuclei",
      mode: "active-aggressive",
      asset: { host: "example.com", port: 443, protocol: "https" },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBeDefined();
  });

  it("blocks active-standard scans in strict_passive mode", () => {
    const decision = engine.canExecute({
      scanner: "zap",
      mode: "active-standard",
      asset: { host: "example.com", port: 80, protocol: "http" },
    });
    expect(decision.allowed).toBe(false);
  });

  it("allows switching to balanced profile", () => {
    engine.setActiveProfile("balanced");
    expect(engine.getActiveProfileId()).toBe("balanced");
  });

  it("allows active-low scans in balanced mode", () => {
    engine.setActiveProfile("balanced");
    const decision = engine.canExecute({
      scanner: "nuclei",
      mode: "active-low",
      asset: { host: "internal.test", port: 443, protocol: "https" },
    });
    expect(decision.allowed).toBe(true);
  });

  it("allows active-aggressive in aggressive_internal mode", () => {
    engine.setActiveProfile("aggressive_internal");
    const decision = engine.canExecute({
      scanner: "zap",
      mode: "active-aggressive",
      asset: { host: "10.0.0.1", port: 8080, protocol: "http" },
    });
    expect(decision.allowed).toBe(true);
  });

  it("returns rate limiter stats", () => {
    const stats = engine.getRateLimiterStats();
    expect(stats).toHaveProperty("globalConcurrent");
    expect(stats).toHaveProperty("hostBuckets");
    expect(stats).toHaveProperty("domainBuckets");
  });

  it("generates an attestation string", () => {
    const attestation = engine.getAttestation();
    expect(typeof attestation).toBe("string");
    expect(attestation.length).toBeGreaterThan(0);
  });

  it("records violations when blocking scans", () => {
    engine.canExecute({
      scanner: "nuclei",
      mode: "active-aggressive",
      asset: { host: "example.com", port: 443, protocol: "https" },
    });
    expect(engine.getViolationCount()).toBeGreaterThan(0);
    const violations = engine.getViolations();
    expect(violations.length).toBeGreaterThan(0);
  });

  it("redacts sensitive headers", () => {
    const headers = {
      "Authorization": "Bearer secret123",
      "Cookie": "session=abc",
      "Content-Type": "application/json",
      "X-Custom": "value",
    };
    const redacted = engine.redactHeaders(headers);
    expect(redacted["Authorization"]).toBe("[REDACTED]");
    expect(redacted["Cookie"]).toBe("[REDACTED]");
    expect(redacted["Content-Type"]).toBe("application/json");
    expect(redacted["X-Custom"]).toBe("value");
  });

  it("provides jitter within configured range", () => {
    const jitter = engine.getJitterMs();
    expect(typeof jitter).toBe("number");
    expect(jitter).toBeGreaterThanOrEqual(0);
  });

  it("returns escalation rules", () => {
    const rules = engine.getEscalationRules();
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBeGreaterThan(0);
  });

  it("serializes to JSON", () => {
    const json = engine.toJSON();
    expect(json).toHaveProperty("activeProfileId");
    expect(json).toHaveProperty("profiles");
    expect(json).toHaveProperty("escalationRules");
  });

  it("throws when setting non-existent profile", () => {
    expect(() => engine.setActiveProfile("nonexistent")).toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. LLM GUARDRAILS TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("LLMGuardrails", () => {
  let guardrails: LLMGuardrails;

  beforeEach(() => {
    resetLLMGuardrails();
    guardrails = getLLMGuardrails();
  });

  it("initializes with guardrails enabled", () => {
    const config = guardrails.getConfig();
    expect(config.enabled).toBe(true);
  });

  it("initializes with general context", () => {
    const config = guardrails.getConfig();
    expect(config.context).toBe("general");
  });

  it("can change context", () => {
    guardrails.setContext("analyst");
    expect(guardrails.getConfig().context).toBe("analyst");
  });

  it("can be enabled and disabled", () => {
    guardrails.setEnabled(false);
    expect(guardrails.getConfig().enabled).toBe(false);
    guardrails.setEnabled(true);
    expect(guardrails.getConfig().enabled).toBe(true);
  });

  it("can toggle strict passive mode", () => {
    guardrails.setStrictPassiveMode(true);
    expect(guardrails.getConfig().strictPassiveMode).toBe(true);
    guardrails.setStrictPassiveMode(false);
    expect(guardrails.getConfig().strictPassiveMode).toBe(false);
  });

  it("starts with zero stats", () => {
    const stats = guardrails.getStats();
    expect(stats.totalCalls).toBe(0);
    expect(stats.blockedCalls).toBe(0);
    expect(stats.sanitizedCalls).toBe(0);
  });

  it("starts with no violations", () => {
    const violations = guardrails.getViolations();
    expect(violations).toHaveLength(0);
  });

  it("serializes to JSON", () => {
    const json = guardrails.toJSON();
    expect(json).toHaveProperty("config");
    expect(json).toHaveProperty("stats");
    expect(json.config).toHaveProperty("enabled");
    expect(json.config).toHaveProperty("context");
  });

  it("supports all valid contexts", () => {
    const contexts = ["analyst", "risk_card", "caldera_hooks", "detection", "phishing", "report", "general"] as const;
    for (const ctx of contexts) {
      guardrails.setContext(ctx);
      expect(guardrails.getConfig().context).toBe(ctx);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. OBSERVATION NORMALIZER TESTS (functional API)
// ═══════════════════════════════════════════════════════════════════════════

describe("ObservationNormalizer", () => {
  it("generates unique observation IDs", () => {
    const id1 = generateObservationId("nmap", "host1", 22, "service_banner", "ssh");
    const id2 = generateObservationId("nmap", "host1", 80, "service_banner", "http");
    expect(id1).not.toBe(id2);
    expect(typeof id1).toBe("string");
    expect(id1.length).toBeGreaterThan(0);
  });

  it("fingerprints data deterministically", () => {
    const fp1 = fingerprintData("hello world");
    const fp2 = fingerprintData("hello world");
    const fp3 = fingerprintData("different data");
    expect(fp1).toBe(fp2);
    expect(fp1).not.toBe(fp3);
  });

  it("redacts sensitive headers", () => {
    const headers = {
      "Authorization": "Bearer secret",
      "Cookie": "session=abc",
      "Content-Type": "application/json",
    };
    const redacted = redactSensitiveHeaders(headers);
    expect(redacted["Authorization"]).toBe("[REDACTED]");
    expect(redacted["Cookie"]).toBe("[REDACTED]");
    expect(redacted["Content-Type"]).toBe("application/json");
  });

  describe("Nmap Adapter", () => {
    it("normalizes nmap scan results", () => {
      const raw: NmapRawResult[] = [{
        host: "192.168.1.1",
        ports: [
          { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9" },
          { port: 443, protocol: "tcp", state: "open", service: "https", version: "nginx 1.22" },
        ],
      }];
      const result = adaptNmapResults(raw);
      expect(result.observations.length).toBe(2);
      expect(result.observations[0].scanner.name).toBe("nmap");
      expect(result.observations[0].scanner.adapter).toBe("nmap-orchestrated");
      expect(result.observations[0].asset.host).toBe("192.168.1.1");
      expect(result.observations[0].asset.port).toBe(22);
      expect(result.observations[0].observationType).toBe("service_banner");
      expect(result.observations[0].evidence.summary).toContain("ssh");
    });

    it("handles empty ports", () => {
      const result = adaptNmapResults([{ host: "test", ports: [] }]);
      expect(result.observations).toHaveLength(0);
    });
  });

  describe("Nuclei Adapter", () => {
    it("normalizes nuclei scan results", () => {
      const raw: NucleiRawResult[] = [{
        templateId: "CVE-2021-44228",
        host: "https://target.com",
        matchedAt: "https://target.com/api",
        severity: "critical",
        name: "Log4Shell RCE",
        description: "Apache Log4j2 Remote Code Execution",
        cve: "CVE-2021-44228",
        cvss: 10.0,
        tags: ["cve", "rce", "log4j"],
        timestamp: new Date().toISOString(),
      }];
      const result = adaptNucleiResults(raw);
      expect(result.observations.length).toBe(1);
      expect(result.observations[0].scanner.name).toBe("nuclei");
      expect(result.observations[0].severity).toBe("critical");
      expect(result.observations[0].evidence.cve).toBe("CVE-2021-44228");
      expect(result.observations[0].observationType).toBe("vulnerability_finding");
    });

    it("handles empty results", () => {
      const result = adaptNucleiResults([]);
      expect(result.observations).toHaveLength(0);
    });
  });

  describe("ZGrab2 Adapter", () => {
    it("normalizes zgrab2 scan results", () => {
      const raw: Zgrab2RawResult[] = [{
        host: "10.0.0.1",
        port: 443,
        protocol: "tls",
        tls: {
          version: "TLS 1.3",
          certSubject: "CN=internal.corp",
          certIssuer: "CN=Corp CA",
          notAfter: "2025-01-01T00:00:00Z",
        },
      }];
      const result = adaptZgrab2Results(raw);
      expect(result.observations.length).toBeGreaterThanOrEqual(1);
      expect(result.observations[0].scanner.name).toBe("zgrab2");
      expect(result.observations[0].asset.host).toBe("10.0.0.1");
    });
  });

  describe("Web Crawler Adapter", () => {
    it("normalizes web crawler results", () => {
      const raw: WebCrawlerRawResult[] = [{
        url: "https://example.com/admin",
        securityHeaders: {
          grade: "F",
          present: ["server"],
          missing: ["strict-transport-security", "content-security-policy"],
        },
        technologies: ["Apache", "PHP"],
      }];
      const result = adaptWebCrawlerResults(raw);
      expect(result.observations.length).toBeGreaterThanOrEqual(1);
      expect(result.observations[0].scanner.name).toBe("web_crawler");
    });
  });

  describe("Domain Intel Adapter", () => {
    it("normalizes domain intel results", () => {
      const raw: DomainIntelRawResult[] = [{
        domain: "example.com",
        dnsRecords: { A: ["93.184.216.34"], MX: ["mail.example.com"] },
        subdomains: ["www.example.com", "api.example.com"],
      }];
      const result = adaptDomainIntelResults(raw);
      expect(result.observations.length).toBeGreaterThanOrEqual(1);
      expect(result.observations[0].scanner.name).toBe("domain_intel");
      expect(result.observations[0].observationType).toBe("dns");
    });
  });

  describe("Vuln Scanner Adapter", () => {
    it("normalizes vuln scanner results", () => {
      const raw: VulnScanRawResult[] = [{
        host: "webapp.example.com",
        port: 443,
        title: "SQL Injection in login form",
        severity: "high",
        cvss: 8.6,
        cve: "CVE-2023-12345",
        confidence: 0.95,
      }];
      const result = adaptVulnScanResults(raw);
      expect(result.observations.length).toBe(1);
      expect(result.observations[0].scanner.name).toBe("vuln_scanner");
      expect(result.observations[0].severity).toBe("high");
      expect(result.observations[0].evidence.cve).toBe("CVE-2023-12345");
      expect(result.observations[0].evidence.cvss).toBe(8.6);
    });
  });

  describe("Signal Derivation", () => {
    it("derives signals from vulnerability observations", () => {
      const nmapObs = adaptNmapResults([{
        host: "192.168.1.1",
        ports: [
          { port: 22, protocol: "tcp", state: "open", service: "ssh" },
          { port: 443, protocol: "tcp", state: "open", service: "https" },
        ],
      }]);
      // Signals may or may not be generated depending on observation types
      const signals = deriveSignals(nmapObs.observations);
      expect(Array.isArray(signals)).toBe(true);
    });

    it("derives signals from nuclei vulnerability findings", () => {
      const nucleiObs = adaptNucleiResults([{
        templateId: "CVE-2021-44228",
        host: "https://target.com",
        severity: "critical",
        cve: "CVE-2021-44228",
        cvss: 10.0,
      }]);
      const signals = deriveSignals(nucleiObs.observations);
      expect(signals.length).toBeGreaterThanOrEqual(1);
      // Should have a vulnerability signal
      const vulnSignals = signals.filter((s) => s.signalType === "vulnerability");
      expect(vulnSignals.length).toBeGreaterThanOrEqual(1);
    });

    it("returns empty array for empty input", () => {
      const signals = deriveSignals([]);
      expect(signals).toHaveLength(0);
    });
  });

  describe("Risk Card Generation", () => {
    it("generates risk cards from signals", () => {
      const nucleiObs = adaptNucleiResults([{
        templateId: "CVE-2021-44228",
        host: "https://target.com",
        severity: "critical",
        cve: "CVE-2021-44228",
        cvss: 10.0,
      }]);
      const signals = deriveSignals(nucleiObs.observations);
      const cards = generateRiskCards(signals);
      expect(cards.length).toBeGreaterThanOrEqual(1);
      expect(cards[0].assetId).toBeDefined();
      expect(cards[0].finalScore).toBeGreaterThan(0);
      expect(cards[0].finalScore).toBeLessThanOrEqual(10);
      expect(cards[0].componentCvss).toBeDefined();
      expect(cards[0].componentCarver).toBeDefined();
      expect(cards[0].componentBia).toBeDefined();
      expect(cards[0].confidenceWeight).toBeDefined();
      expect(cards[0].summary).toBeDefined();
      expect(cards[0].recommendations).toBeDefined();
    });

    it("returns empty array for empty input", () => {
      const cards = generateRiskCards([]);
      expect(cards).toHaveLength(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. INTEGRATION TESTS (Singleton pattern)
// ═══════════════════════════════════════════════════════════════════════════

describe("SSIL Integration", () => {
  it("singletons return consistent instances", () => {
    resetScanPolicyEngine();
    const engine1 = getScanPolicyEngine();
    const engine2 = getScanPolicyEngine();
    expect(engine1).toBe(engine2);

    resetLLMGuardrails();
    const guard1 = getLLMGuardrails();
    const guard2 = getLLMGuardrails();
    expect(guard1).toBe(guard2);
  });

  it("reset creates new instances", () => {
    const engine1 = getScanPolicyEngine();
    resetScanPolicyEngine();
    const engine2 = getScanPolicyEngine();
    expect(engine1).not.toBe(engine2);
  });

  it("policy engine and normalizer work together", () => {
    resetScanPolicyEngine();
    const engine = getScanPolicyEngine();
    engine.setActiveProfile("aggressive_internal");

    // Check if a scan is allowed before normalizing (nmap_orchestrated allowed in aggressive_internal)
    const decision = engine.canExecute({
      scanner: "nmap_orchestrated",
      mode: "passive",
      asset: { host: "192.168.1.1", port: 22, protocol: "tcp" },
    });
    expect(decision.allowed).toBe(true);

    // Normalize the results
    const result = adaptNmapResults([{
      host: "192.168.1.1",
      ports: [{ port: 22, protocol: "tcp", state: "open", service: "ssh" }],
    }]);
    expect(result.observations.length).toBe(1);

    // Derive signals
    const signals = deriveSignals(result.observations);
    expect(Array.isArray(signals)).toBe(true);
  });

  it("full pipeline: scan → normalize → signals → risk cards", () => {
    // 1. Policy check
    resetScanPolicyEngine();
    const engine = getScanPolicyEngine();
    engine.setActiveProfile("balanced");
    const decision = engine.canExecute({
      scanner: "nuclei",
      mode: "active-low",
      asset: { host: "target.com", port: 443, protocol: "https" },
    });
    expect(decision.allowed).toBe(true);

    // 2. Normalize scan results
    const nucleiResult = adaptNucleiResults([{
      templateId: "CVE-2021-44228",
      host: "https://target.com",
      severity: "critical",
      cve: "CVE-2021-44228",
      cvss: 10.0,
    }]);
    expect(nucleiResult.observations.length).toBe(1);

    // 3. Derive signals
    const signals = deriveSignals(nucleiResult.observations);
    expect(signals.length).toBeGreaterThanOrEqual(1);

    // 4. Generate risk cards
    const cards = generateRiskCards(signals);
    expect(cards.length).toBeGreaterThanOrEqual(1);
    expect(cards[0].finalScore).toBeGreaterThan(0);
  });
});
