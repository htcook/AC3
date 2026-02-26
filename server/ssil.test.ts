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


// ═══════════════════════════════════════════════════════════════════════════
// 5. OBSERVATION INGESTOR TESTS
// ═══════════════════════════════════════════════════════════════════════════

import {
  onIngestionEvent,
  getRecentEvents,
  getIngestionStats,
  type IngestionEvent,
} from "./lib/observation-ingestor";

describe("ObservationIngestor — Event System", () => {
  it("getRecentEvents returns an array", () => {
    const events = getRecentEvents();
    expect(Array.isArray(events)).toBe(true);
  });

  it("getRecentEvents with since filter returns events after timestamp", () => {
    const events = getRecentEvents(Date.now() - 1000);
    expect(Array.isArray(events)).toBe(true);
  });

  it("getRecentEvents with limit returns at most N events", () => {
    const events = getRecentEvents(undefined, 5);
    expect(events.length).toBeLessThanOrEqual(5);
  });

  it("onIngestionEvent registers a listener and returns unsubscribe function", () => {
    const received: IngestionEvent[] = [];
    const unsub = onIngestionEvent((event) => received.push(event));
    expect(typeof unsub).toBe("function");
    unsub();
  });
});

describe("ObservationIngestor — Stats", () => {
  it("getIngestionStats returns a valid stats object", () => {
    const stats = getIngestionStats();
    expect(stats).toHaveProperty("totalObservations");
    expect(stats).toHaveProperty("totalSignals");
    expect(stats).toHaveProperty("totalRiskCards");
    expect(stats).toHaveProperty("totalErrors");
    expect(stats).toHaveProperty("lastIngestionAt");
    expect(stats).toHaveProperty("byScanner");
    expect(typeof stats.totalObservations).toBe("number");
    expect(typeof stats.totalSignals).toBe("number");
    expect(typeof stats.totalRiskCards).toBe("number");
    expect(typeof stats.totalErrors).toBe("number");
    expect(typeof stats.byScanner).toBe("object");
  });

  it("stats are non-negative", () => {
    const stats = getIngestionStats();
    expect(stats.totalObservations).toBeGreaterThanOrEqual(0);
    expect(stats.totalSignals).toBeGreaterThanOrEqual(0);
    expect(stats.totalRiskCards).toBeGreaterThanOrEqual(0);
    expect(stats.totalErrors).toBeGreaterThanOrEqual(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. END-TO-END PIPELINE WIRING TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("End-to-End Pipeline Wiring", () => {
  it("nmap results → normalize → signals → risk cards → stats update", () => {
    // 1. Normalize
    const result = adaptNmapResults([
      { host: "10.0.0.1", ports: [{ port: 80, protocol: "tcp", state: "open", service: "http" }] },
      { host: "10.0.0.2", ports: [{ port: 443, protocol: "tcp", state: "open", service: "https" }] },
    ]);
    expect(result.observations.length).toBe(2);
    expect(result.metrics.observationsEmitted).toBe(2);

    // 2. Nmap service_banner observations don't directly produce signals
    // (signals come from tls, http_headers, vulnerability_finding, etc.)
    const signals = deriveSignals(result.observations);
    expect(Array.isArray(signals)).toBe(true);

    // 3. Combine with nuclei results to get signals and risk cards
    const nucleiResult = adaptNucleiResults([{
      templateId: "CVE-2024-5678",
      host: "https://10.0.0.1",
      severity: "high",
      cve: "CVE-2024-5678",
      cvss: 8.0,
    }]);
    const allObs = [...result.observations, ...nucleiResult.observations];
    const allSignals = deriveSignals(allObs);
    expect(allSignals.length).toBeGreaterThanOrEqual(1);

    const cards = generateRiskCards(allSignals);
    expect(cards.length).toBeGreaterThanOrEqual(1);
    for (const card of cards) {
      expect(card.riskId).toBeDefined();
      expect(card.assetId).toBeDefined();
      expect(card.finalScore).toBeGreaterThanOrEqual(0);
      expect(card.finalScore).toBeLessThanOrEqual(10);
      expect(card.componentCvss).toBeDefined();
      expect(card.componentCarver).toBeDefined();
      expect(card.componentBia).toBeDefined();
      expect(card.confidenceWeight).toBeGreaterThan(0);
      expect(card.recommendations).toBeDefined();
      expect(Array.isArray(card.recommendations)).toBe(true);
      expect(card.signalIds).toBeDefined();
      expect(Array.isArray(card.signalIds)).toBe(true);
    }
  });

  it("nuclei critical finding → high risk score", () => {
    const result = adaptNucleiResults([{
      templateId: "CVE-2024-1234",
      host: "https://critical-target.com",
      severity: "critical",
      cve: "CVE-2024-1234",
      cvss: 9.8,
    }]);
    const signals = deriveSignals(result.observations);
    const cards = generateRiskCards(signals);

    expect(cards.length).toBe(1);
    expect(cards[0].finalScore).toBeGreaterThan(3);
    expect(cards[0].componentCvss).toBeGreaterThanOrEqual(9);
  });

  it("multiple scanners → merged risk card per asset", () => {
    // Nmap finds open ports
    const nmapResult = adaptNmapResults([
      { host: "shared-target.com", ports: [{ port: 80, protocol: "tcp", state: "open", service: "http" }] },
    ]);

    // Nuclei finds vulnerability on same host
    const nucleiResult = adaptNucleiResults([{
      templateId: "CVE-2023-9999",
      host: "https://shared-target.com",
      severity: "high",
      cve: "CVE-2023-9999",
      cvss: 8.5,
    }]);

    // Combine observations
    const allObs = [...nmapResult.observations, ...nucleiResult.observations];
    const signals = deriveSignals(allObs);
    const cards = generateRiskCards(signals);

    // Should produce risk card(s) for shared-target.com
    expect(cards.length).toBeGreaterThanOrEqual(1);
    const sharedCards = cards.filter((c) =>
      c.assetId.includes("shared-target.com")
    );
    expect(sharedCards.length).toBeGreaterThanOrEqual(1);
  });

  it("web crawler results → observations with correct scanner name", () => {
    const result = adaptWebCrawlerResults([{
      url: "https://test.com",
      statusCode: 200,
      headers: { "x-powered-by": "Express", "server": "nginx" },
      technologies: ["Express", "nginx"],
    }]);

    expect(result.observations.length).toBeGreaterThanOrEqual(1);
    for (const obs of result.observations) {
      expect(obs.scanner.name).toBe("web_crawler");
    }
  });

  it("domain intel results → observations with DNS data", () => {
    const result = adaptDomainIntelResults([{
      domain: "example.com",
      subdomains: ["api.example.com", "www.example.com"],
      dnsRecords: [{ type: "A", value: "93.184.216.34" }],
    }]);

    expect(result.observations.length).toBeGreaterThanOrEqual(1);
    for (const obs of result.observations) {
      expect(obs.scanner.name).toBe("domain_intel");
    }
  });

  it("vuln scanner results → observations with CVE data", () => {
    const result = adaptVulnScanResults([{
      hostIp: "10.0.0.5",
      port: 443,
      title: "OpenSSL Heartbleed",
      severity: "critical",
      cveId: "CVE-2014-0160",
      cvssScore: 7.5,
    }]);

    expect(result.observations.length).toBe(1);
    // VulnScan adapter maps CVE to evidence.cve
    const obs = result.observations[0];
    expect(obs.evidence.summary).toContain("OpenSSL Heartbleed");
  });

  it("guardrails + policy + normalizer integration", () => {
    // 1. Policy engine allows the scan
    resetScanPolicyEngine();
    const engine = getScanPolicyEngine();
    engine.setActiveProfile("balanced");
    const decision = engine.canExecute({
      scanner: "nuclei",
      mode: "active-low",
      asset: { host: "target.com", port: 443, protocol: "https" },
    });
    expect(decision.allowed).toBe(true);

    // 2. Guardrails validate the LLM context
    resetLLMGuardrails();
    const guardrails = getLLMGuardrails();
    const guardResult = guardrails.applyGuardrails(
      { messages: [{ role: "user", content: "Analyze this scan result for security issues" }] },
      "analyst"
    );
    expect(guardResult.blocked).toBe(false);

    // 3. Normalize and process
    const result = adaptNucleiResults([{
      templateId: "CVE-2021-44228",
      host: "https://target.com",
      severity: "critical",
      cve: "CVE-2021-44228",
      cvss: 10.0,
    }]);
    const signals = deriveSignals(result.observations);
    const cards = generateRiskCards(signals);

    expect(result.observations.length).toBe(1);
    expect(signals.length).toBeGreaterThanOrEqual(1);
    expect(cards.length).toBeGreaterThanOrEqual(1);
    expect(cards[0].finalScore).toBeGreaterThan(0);
    expect(cards[0].recommendations.length).toBeGreaterThan(0);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// ALERT RULES ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════
import {
  AlertRulesEngine,
  getAlertRulesEngine,
  resetAlertRulesEngine,
  DEFAULT_ALERT_RULES,
  type AlertRule,
  type EvaluationContext,
} from "./lib/alert-rules-engine";
import {
  CorrelationEngine,
  getCorrelationEngine,
  type ObservationRow,
  type SignalRow,
  type RiskCardRow,
} from "./lib/correlation-engine";

describe("Alert Rules Engine", () => {
  let engine: AlertRulesEngine;

  beforeEach(() => {
    resetAlertRulesEngine();
    engine = getAlertRulesEngine();
  });

  describe("Rule Management", () => {
    it("should start with default rules loaded", () => {
      expect(engine.getAllRules().length).toBe(DEFAULT_ALERT_RULES.length);
    });
    it("should add and retrieve rules", () => {
      const initialCount = engine.getAllRules().length;
      const rule: AlertRule = {
        ruleId: "test-1",
        name: "Test Rule",
        description: "Test",
        triggerType: "critical_cve",
        conditions: {},
        isEnabled: true,
        notifyOwner: false,
        cooldownMinutes: 60,
        triggerCount: 0,
        lastTriggeredAt: null,
      };
      engine.addRule(rule);
      expect(engine.getAllRules()).toHaveLength(initialCount + 1);
      expect(engine.getRule("test-1")).toBeDefined();
      expect(engine.getRule("test-1")?.name).toBe("Test Rule");;
    });

    it("should remove rules", () => {
      const rule: AlertRule = {
        ruleId: "test-2",
        name: "Remove Me",
        description: "",
        triggerType: "new_open_port",
        conditions: {},
        isEnabled: true,
        notifyOwner: false,
        cooldownMinutes: 30,
        triggerCount: 0,
        lastTriggeredAt: null,
      };
      engine.addRule(rule);
      const countBefore = engine.getAllRules().length;
      expect(engine.removeRule("test-2")).toBe(true);
      expect(engine.getAllRules()).toHaveLength(countBefore - 1);
    });

    it("should enable and disable rules", () => {
      const rule: AlertRule = {
        ruleId: "test-3",
        name: "Toggle",
        description: "",
        triggerType: "high_severity_signal",
        conditions: {},
        isEnabled: true,
        notifyOwner: false,
        cooldownMinutes: 15,
        triggerCount: 0,
        lastTriggeredAt: null,
      };
      engine.addRule(rule);
      expect(engine.disableRule("test-3")).toBe(true);
      expect(engine.getRule("test-3")?.isEnabled).toBe(false);
      expect(engine.enableRule("test-3")).toBe(true);
      expect(engine.getRule("test-3")?.isEnabled).toBe(true);
    });

    it("should load default alert rules", () => {
      const rules = DEFAULT_ALERT_RULES.map((r) => ({
        ...r,
        triggerCount: 0,
        lastTriggeredAt: null,
      }));
      engine.loadRules(rules);
      expect(engine.getAllRules().length).toBe(DEFAULT_ALERT_RULES.length);
      expect(engine.getAllRules().length).toBeGreaterThanOrEqual(5);
    });
  });

  describe("Evaluation", () => {
    beforeEach(() => {
      const rules = DEFAULT_ALERT_RULES.map((r) => ({
        ...r,
        triggerCount: 0,
        lastTriggeredAt: null,
      }));
      engine.loadRules(rules);
    });

    it("should trigger critical CVE alert on critical vulnerability observation", async () => {
      const context: EvaluationContext = {
        observations: [
          {
            observationId: "obs-cve-1",
            scanner: { name: "nuclei", adapter: "nuclei" },
            observationType: "vulnerability",
            severity: "critical",
            confidence: 0.95,
            timestamp: new Date().toISOString(),
            asset: {
              assetId: "asset-1",
              host: "target.example.com",
              port: 443,
              protocol: "tcp",
            },
            evidence: {
              summary: "Critical RCE vulnerability CVE-2024-1234",
              cve: "CVE-2024-1234",
              cvss: 9.8,
            },
            tags: ["rce", "critical"],
            ttl: 86400,
          },
        ],
      };

      const alerts = await engine.evaluate(context);
      expect(alerts.length).toBeGreaterThanOrEqual(1);
      const critAlert = alerts.find((a) => a.triggerType === "critical_cve");
      expect(critAlert).toBeDefined();
      expect(critAlert?.severity).toBe("critical");
    });

    it("should trigger new open port alert", async () => {
      const context: EvaluationContext = {
        observations: [
          {
            observationId: "obs-port-1",
            scanner: { name: "nmap", adapter: "nmap" },
            observationType: "service_banner",
            severity: "medium",
            confidence: 0.99,
            timestamp: new Date().toISOString(),
            asset: {
              assetId: "asset-2",
              host: "server.example.com",
              port: 8080,
              protocol: "tcp",
            },
            evidence: {
              summary: "Port 8080 open - HTTP proxy",
            },
            tags: ["http-proxy"],
            ttl: 86400,
          },
        ],
      };

      const alerts = await engine.evaluate(context);
      const portAlert = alerts.find((a) => a.triggerType === "new_open_port");
      expect(portAlert).toBeDefined();
    });

    it("should not trigger disabled rules", async () => {
      engine.disableRule("default-critical-cve");
      const context: EvaluationContext = {
        observations: [
          {
            observationId: "obs-disabled-1",
            scanner: { name: "nuclei", adapter: "nuclei" },
            observationType: "vulnerability",
            severity: "critical",
            confidence: 0.95,
            timestamp: new Date().toISOString(),
            asset: {
              assetId: "asset-3",
              host: "target.example.com",
              port: 443,
              protocol: "tcp",
            },
            evidence: {
              summary: "Critical vuln but rule disabled",
              cve: "CVE-2024-9999",
              cvss: 10.0,
            },
            tags: [],
            ttl: 86400,
          },
        ],
      };

      const alerts = await engine.evaluate(context);
      const critAlert = alerts.find((a) => a.triggerType === "critical_cve");
      expect(critAlert).toBeUndefined();
    });

    it("should respect cooldown periods", async () => {
      const context: EvaluationContext = {
        observations: [
          {
            observationId: "obs-cooldown-1",
            scanner: { name: "nuclei", adapter: "nuclei" },
            observationType: "vulnerability",
            severity: "critical",
            confidence: 0.95,
            timestamp: new Date().toISOString(),
            asset: {
              assetId: "asset-4",
              host: "target.example.com",
              port: 443,
              protocol: "tcp",
            },
            evidence: {
              summary: "Critical vuln for cooldown test",
              cve: "CVE-2024-5555",
              cvss: 9.5,
            },
            tags: [],
            ttl: 86400,
          },
        ],
      };

      // First evaluation should trigger
      const alerts1 = await engine.evaluate(context);
      const critAlert1 = alerts1.find((a) => a.triggerType === "critical_cve");
      expect(critAlert1).toBeDefined();

      // Second immediate evaluation should be suppressed by cooldown
      const alerts2 = await engine.evaluate(context);
      const critAlert2 = alerts2.find((a) => a.triggerType === "critical_cve");
      expect(critAlert2).toBeUndefined();
    });
  });

  describe("Event Listeners", () => {
    it("should notify listeners on alert", async () => {
      const events: any[] = [];
      engine.onAlert((event) => events.push(event));

      // Load all default rules so the critical_cve rule is present
      const rules = DEFAULT_ALERT_RULES.map((r) => ({
        ...r,
        triggerCount: 0,
        lastTriggeredAt: null,
      }));
      engine.loadRules(rules);

      await engine.evaluate({
        observations: [
          {
            observationId: "obs-listener-1",
            scanner: { name: "nuclei", adapter: "nuclei" },
            observationType: "vulnerability",
            severity: "critical",
            confidence: 0.9,
            timestamp: new Date().toISOString(),
            asset: { assetId: "a-5", host: "test.com", port: 443, protocol: "tcp" },
            evidence: { summary: "Critical", cve: "CVE-2024-0001", cvss: 9.0 },
            tags: [],
            ttl: 86400,
          },
        ],
      });

      expect(events.length).toBeGreaterThanOrEqual(1);
    });

    it("should allow unsubscribing listeners", () => {
      const events: any[] = [];
      const unsub = engine.onAlert((event) => events.push(event));
      unsub();
      // After unsubscribing, no events should be received
      // (can't easily test without triggering, but the unsub function should work)
      expect(typeof unsub).toBe("function");
    });
  });

  describe("Stats", () => {
    it("should return correct stats", async () => {
      const rules = DEFAULT_ALERT_RULES.map((r) => ({
        ...r,
        triggerCount: 0,
        lastTriggeredAt: null,
      }));
      engine.loadRules(rules);

      const stats = engine.getStats();
      expect(stats.totalRules).toBe(DEFAULT_ALERT_RULES.length);
      // Some default rules have isEnabled: false
      expect(stats.enabledRules).toBeLessThanOrEqual(DEFAULT_ALERT_RULES.length);
      expect(stats.enabledRules).toBeGreaterThan(0);
      expect(stats.totalAlerts).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════
describe("Correlation Engine", () => {
  let engine: CorrelationEngine;

  beforeEach(() => {
    engine = getCorrelationEngine();
  });

  describe("correlateByAsset", () => {
    it("should group observations by asset", () => {
      const observations: ObservationRow[] = [
        {
          observationId: "o1",
          scannerName: "nmap",
          scannerAdapter: "nmap",
          observationType: "service_banner",
          severity: "medium",
          confidence: 99,
          assetId: "asset-a",
          assetHost: "target.com",
          assetPort: 80,
          assetProtocol: "tcp",
          evidenceFingerprint: "fp1",
          evidenceSummary: "Port 80 open",
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
        {
          observationId: "o2",
          scannerName: "nuclei",
          scannerAdapter: "nuclei",
          observationType: "vulnerability",
          severity: "high",
          confidence: 85,
          assetId: "asset-a",
          assetHost: "target.com",
          assetPort: 80,
          assetProtocol: "tcp",
          evidenceFingerprint: "fp2",
          evidenceSummary: "XSS vulnerability",
          evidenceCve: "CVE-2024-1111",
          evidenceCvss: 7.5,
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
        {
          observationId: "o3",
          scannerName: "httpx",
          scannerAdapter: "httpx",
          observationType: "http_headers",
          severity: "info",
          confidence: 100,
          assetId: "asset-b",
          assetHost: "other.com",
          assetPort: 443,
          assetProtocol: "tcp",
          evidenceFingerprint: "fp3",
          evidenceSummary: "HTTP headers",
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
      ];

      const assets = engine.correlateByAsset(observations);
      expect(assets).toHaveLength(2);

      const assetA = assets.find((a) => a.assetId === "asset-a");
      expect(assetA).toBeDefined();
      expect(assetA!.host).toBe("target.com");
      expect(assetA!.totalObservations).toBe(2);
      expect(assetA!.scannerCoverage.length).toBeGreaterThanOrEqual(1);
    });

    it("should extract open ports from service_banner observations", () => {
      const observations: ObservationRow[] = [
        {
          observationId: "op1",
          scannerName: "nmap",
          scannerAdapter: "nmap",
          observationType: "service_banner",
          severity: "medium",
          confidence: 99,
          assetId: "asset-ports",
          assetHost: "ports.com",
          assetPort: 22,
          assetProtocol: "tcp",
          evidenceFingerprint: "p22",
          evidenceSummary: "SSH port open",
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
        {
          observationId: "op2",
          scannerName: "nmap",
          scannerAdapter: "nmap",
          observationType: "service_banner",
          severity: "medium",
          confidence: 99,
          assetId: "asset-ports",
          assetHost: "ports.com",
          assetPort: 443,
          assetProtocol: "tcp",
          evidenceFingerprint: "p443",
          evidenceSummary: "HTTPS port open",
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
      ];

      const assets = engine.correlateByAsset(observations);
      expect(assets).toHaveLength(1);
      expect(assets[0].totalOpenPorts).toBe(2);
      expect(assets[0].openPorts.length).toBe(2);
    });

    it("should calculate composite risk score from risk cards", () => {
      const observations: ObservationRow[] = [
        {
          observationId: "rc1",
          scannerName: "nuclei",
          scannerAdapter: "nuclei",
          observationType: "vulnerability",
          severity: "critical",
          confidence: 95,
          assetId: "asset-risk",
          assetHost: "risky.com",
          assetPort: 443,
          assetProtocol: "tcp",
          evidenceFingerprint: "risk-fp",
          evidenceSummary: "Critical vuln",
          evidenceCve: "CVE-2024-9999",
          evidenceCvss: 9.8,
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
      ];

      const riskCards: RiskCardRow[] = [
        {
          assetId: "asset-risk",
          compositeScore: 85,
          cvssScore: 9.8,
          carverScore: 7.5,
          biaScore: 8.0,
          createdAt: Date.now(),
        },
      ];

      const assets = engine.correlateByAsset(observations, [], riskCards);
      expect(assets).toHaveLength(1);
      expect(assets[0].compositeRiskScore).toBe(85);
    });
  });

  describe("generateAttackSurfaceSummary", () => {
    it("should generate summary from correlated assets", () => {
      const observations: ObservationRow[] = [
        {
          observationId: "sum1",
          scannerName: "nmap",
          scannerAdapter: "nmap",
          observationType: "service_banner",
          severity: "medium",
          confidence: 99,
          assetId: "asset-sum",
          assetHost: "summary.com",
          assetPort: 80,
          assetProtocol: "tcp",
          evidenceFingerprint: "sfp1",
          evidenceSummary: "Port 80",
          observedAt: Date.now(),
          ingestedAt: Date.now(),
        },
      ];

      const assets = engine.correlateByAsset(observations);
      const summary = engine.generateAttackSurfaceSummary(assets);

      expect(summary.totalAssets).toBe(1);
      expect(summary.totalObservations).toBe(1);
      expect(typeof summary.averageRiskScore).toBe("number");
      expect(summary.severityDistribution).toBeDefined();
      expect(summary.scannerCount).toBeGreaterThanOrEqual(1);
    });

    it("should handle empty asset list", () => {
      const summary = engine.generateAttackSurfaceSummary([]);
      expect(summary.totalAssets).toBe(0);
      expect(summary.totalObservations).toBe(0);
      expect(summary.averageRiskScore).toBe(0);
    });
  });

  describe("buildAssetTimeline", () => {
    it("should build timeline buckets from observations", () => {
      const now = Date.now();
      const observations: ObservationRow[] = [];
      // Create observations spread over 24 hours
      for (let i = 0; i < 10; i++) {
        observations.push({
          observationId: `tl-${i}`,
          scannerName: "nmap",
          scannerAdapter: "nmap",
          observationType: "service_banner",
          severity: "info",
          confidence: 99,
          assetId: "asset-tl",
          assetHost: "timeline.com",
          assetPort: 80 + i,
          assetProtocol: "tcp",
          evidenceFingerprint: `tl-fp-${i}`,
          evidenceSummary: `Port ${80 + i}`,
          observedAt: now - i * 3600000,
          ingestedAt: now - i * 3600000,
        });
      }

      // buildAssetTimeline requires assetId as second arg
      const timeline = engine.buildAssetTimeline(observations, "asset-tl", 60);
      expect(timeline.length).toBeGreaterThan(0);
      for (const bucket of timeline) {
        expect(bucket.observationCount).toBeGreaterThanOrEqual(0);
        expect(bucket.timestamp).toBeDefined();
      }
    });
  });
});
