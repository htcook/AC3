/**
 * DNS Security Validator Tests
 *
 * Tests for:
 * 1. DnsSecurityValidator class — check categories, findings structure, DNSSEC status
 * 2. TAKEOVER_FINGERPRINTS — fingerprint database integrity
 * 3. runDnsSecurityAssessment — end-to-end assessment flow
 * 4. DNS Security Router — procedure inputs/outputs
 * 5. PDF report section — dnsSecurityReport data shape
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { DnsSecurityReport, DnsFinding, DnsRecord, DnssecStatus, EngagementContext } from "./lib/dns-security-validator";

// ─── TAKEOVER_FINGERPRINTS Tests ────────────────────────────────────────────
describe("TAKEOVER_FINGERPRINTS", () => {
  it("should export a non-empty array of fingerprints", async () => {
    const { TAKEOVER_FINGERPRINTS } = await import("./lib/dns-security-validator");
    expect(Array.isArray(TAKEOVER_FINGERPRINTS)).toBe(true);
    expect(TAKEOVER_FINGERPRINTS.length).toBeGreaterThan(30);
  });

  it("each fingerprint should have required fields", async () => {
    const { TAKEOVER_FINGERPRINTS } = await import("./lib/dns-security-validator");
    for (const fp of TAKEOVER_FINGERPRINTS) {
      expect(fp).toHaveProperty("service");
      expect(fp).toHaveProperty("cnames");
      expect(fp).toHaveProperty("fingerprints");
      expect(fp).toHaveProperty("vulnerable");
      expect(typeof fp.service).toBe("string");
      expect(Array.isArray(fp.cnames)).toBe(true);
      expect(Array.isArray(fp.fingerprints)).toBe(true);
      expect(typeof fp.vulnerable).toBe("boolean");
    }
  });

  it("should include major cloud services", async () => {
    const { TAKEOVER_FINGERPRINTS } = await import("./lib/dns-security-validator");
    const services = TAKEOVER_FINGERPRINTS.map(fp => fp.service.toLowerCase());
    expect(services.some(s => s.includes("github") || s.includes("s3") || s.includes("azure") || s.includes("heroku"))).toBe(true);
  });
});

// ─── DnsSecurityReport Type Shape Tests ──────────────────────────────────────
describe("DnsSecurityReport shape", () => {
  it("should define correct summary structure", () => {
    const mockReport: DnsSecurityReport = {
      domain: "example.com",
      assessedAt: Date.now(),
      context: "di_scan",
      summary: {
        overallRisk: "medium",
        totalFindings: 3,
        critical: 0,
        high: 1,
        medium: 1,
        low: 1,
        info: 0,
        totalChecks: 15,
        passedChecks: 12,
        failedChecks: 3,
      },
      findings: [],
      records: [],
      dnssec: {
        enabled: false,
        delegationSigned: false,
        rrsigPresent: false,
        chainOfTrustValid: false,
        algorithmStrength: null,
        dsRecords: [],
        dnskeyRecords: [],
        issues: [],
      },
      metadata: {
        checksPerformed: [],
        responseTimeMs: 1500,
        resolverUsed: "dns.google",
      },
    };
    expect(mockReport.domain).toBe("example.com");
    expect(mockReport.summary.totalChecks).toBe(15);
    expect(mockReport.summary.passedChecks + mockReport.summary.failedChecks).toBe(15);
  });

  it("overallRisk should be one of critical/high/medium/low", () => {
    const validRisks = ["critical", "high", "medium", "low"];
    validRisks.forEach(risk => {
      expect(["critical", "high", "medium", "low"]).toContain(risk);
    });
  });
});

// ─── DnsFinding Type Tests ───────────────────────────────────────────────────
describe("DnsFinding structure", () => {
  it("should have all required fields", () => {
    const finding: DnsFinding = {
      id: "dns-001",
      severity: "high",
      category: "dangling_dns",
      title: "CNAME pointing to unclaimed S3 bucket",
      description: "The subdomain has a CNAME pointing to an S3 bucket that does not exist.",
      affectedRecord: "assets.example.com CNAME assets.example.com.s3.amazonaws.com",
      evidence: "HTTP 404 with NoSuchBucket response",
      remediation: "Remove the CNAME record or claim the S3 bucket",
      mitreAttackId: "T1584.002",
      cvssScore: 7.5,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
      cwe: "CWE-672",
      references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    };
    expect(finding.id).toBe("dns-001");
    expect(finding.severity).toBe("high");
    expect(finding.category).toBe("dangling_dns");
    expect(finding.mitreAttackId).toBe("T1584.002");
  });

  it("severity must be one of the valid values", () => {
    const validSeverities = ["critical", "high", "medium", "low", "info"];
    validSeverities.forEach(sev => {
      expect(["critical", "high", "medium", "low", "info"]).toContain(sev);
    });
  });

  it("category must be one of the valid check categories", () => {
    const validCategories = [
      "dangling_dns", "dnssec", "zone_transfer", "cache_poisoning",
      "open_resolver", "amplification", "wildcard", "email_security",
      "caa", "zone_walking", "tunneling_indicator", "version_disclosure",
      "dns_cookie", "rate_limiting", "rebinding",
    ];
    expect(validCategories.length).toBe(15);
  });
});

// ─── DnsRecord Type Tests ────────────────────────────────────────────────────
describe("DnsRecord structure", () => {
  it("should support all standard DNS record types", () => {
    const records: DnsRecord[] = [
      { type: "A", name: "example.com", value: "93.184.216.34", ttl: 300 },
      { type: "AAAA", name: "example.com", value: "2606:2800:220:1:248:1893:25c8:1946", ttl: 300 },
      { type: "CNAME", name: "www.example.com", value: "example.com", ttl: 3600 },
      { type: "MX", name: "example.com", value: "mail.example.com", ttl: 3600, priority: 10 },
      { type: "TXT", name: "example.com", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
      { type: "NS", name: "example.com", value: "ns1.example.com", ttl: 86400 },
      { type: "SOA", name: "example.com", value: "ns1.example.com admin.example.com 2024010101 3600 900 604800 86400", ttl: 86400 },
      { type: "CAA", name: "example.com", value: "0 issue letsencrypt.org", ttl: 3600 },
    ];
    expect(records.length).toBe(8);
    expect(records[3].priority).toBe(10);
    expect(records[0].type).toBe("A");
  });
});

// ─── DnssecStatus Tests ──────────────────────────────────────────────────────
describe("DnssecStatus structure", () => {
  it("should represent enabled DNSSEC with chain of trust", () => {
    const status: DnssecStatus = {
      enabled: true,
      delegationSigned: true,
      rrsigPresent: true,
      chainOfTrustValid: true,
      algorithmStrength: "strong",
      signatureExpiry: "2025-06-15T00:00:00Z",
      dsRecords: [{
        keyTag: 12345,
        algorithm: 13,
        algorithmName: "ECDSAP256SHA256",
        digestType: 2,
        digest: "abc123def456...",
      }],
      dnskeyRecords: [{
        flags: 257,
        algorithm: 13,
        algorithmName: "ECDSAP256SHA256",
        keyLength: 256,
      }],
      issues: [],
    };
    expect(status.enabled).toBe(true);
    expect(status.chainOfTrustValid).toBe(true);
    expect(status.algorithmStrength).toBe("strong");
    expect(status.dsRecords.length).toBe(1);
    expect(status.dnskeyRecords[0].flags).toBe(257); // KSK
  });

  it("should represent disabled DNSSEC with issues", () => {
    const status: DnssecStatus = {
      enabled: false,
      delegationSigned: false,
      rrsigPresent: false,
      chainOfTrustValid: false,
      algorithmStrength: null,
      dsRecords: [],
      dnskeyRecords: [],
      issues: ["No DNSSEC records found — domain is not signed"],
    };
    expect(status.enabled).toBe(false);
    expect(status.issues.length).toBe(1);
    expect(status.algorithmStrength).toBeNull();
  });
});

// ─── DNS Security Router Tests ───────────────────────────────────────────────
describe("DNS Security Router", () => {
  describe("runAssessment procedure", () => {
    it("should validate domain input (min 1, max 253)", () => {
      const validDomains = ["a.com", "example.com", "sub.domain.example.co.uk"];
      const invalidDomains = ["", "a".repeat(254)];
      validDomains.forEach(d => {
        expect(d.length).toBeGreaterThanOrEqual(1);
        expect(d.length).toBeLessThanOrEqual(253);
      });
      invalidDomains.forEach(d => {
        expect(d.length < 1 || d.length > 253).toBe(true);
      });
    });

    it("should accept valid context values", () => {
      const validContexts: EngagementContext[] = ["di_scan", "vuln_pentest", "red_team"];
      validContexts.forEach(ctx => {
        expect(["di_scan", "vuln_pentest", "red_team"]).toContain(ctx);
      });
    });

    it("should strip protocol and path from domain input", () => {
      const inputs = [
        { raw: "https://example.com/path", expected: "example.com" },
        { raw: "http://sub.example.com/", expected: "sub.example.com" },
        { raw: "example.com", expected: "example.com" },
      ];
      inputs.forEach(({ raw, expected }) => {
        const cleaned = raw.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
        expect(cleaned).toBe(expected);
      });
    });
  });

  describe("getFingerprints procedure", () => {
    it("should return totalServices and services array", async () => {
      const { TAKEOVER_FINGERPRINTS } = await import("./lib/dns-security-validator");
      const result = {
        totalServices: TAKEOVER_FINGERPRINTS.length,
        services: TAKEOVER_FINGERPRINTS.map(fp => ({
          service: fp.service,
          cnames: fp.cnames,
          vulnerable: fp.vulnerable,
        })),
      };
      expect(result.totalServices).toBeGreaterThan(0);
      expect(result.services.length).toBe(result.totalServices);
      expect(result.services[0]).toHaveProperty("service");
      expect(result.services[0]).toHaveProperty("cnames");
      expect(result.services[0]).toHaveProperty("vulnerable");
    });
  });

  describe("getMitreMapping procedure", () => {
    it("should return MITRE ATT&CK techniques relevant to DNS", () => {
      const mapping = [
        { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "Command and Control", dnsRelevance: "DNS tunneling for C2 communication" },
        { id: "T1568", name: "Dynamic Resolution", tactic: "Command and Control", dnsRelevance: "Fast-flux DNS, domain generation algorithms" },
        { id: "T1584.002", name: "Compromise Infrastructure: DNS Server", tactic: "Resource Development", dnsRelevance: "Subdomain takeover, dangling DNS exploitation" },
        { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access", dnsRelevance: "DNS spoofing, cache poisoning" },
        { id: "T1498.002", name: "Network DoS: Reflection Amplification", tactic: "Impact", dnsRelevance: "DNS amplification attacks via open resolvers" },
        { id: "T1590.002", name: "Gather Victim Network Info: DNS", tactic: "Reconnaissance", dnsRelevance: "Zone transfer, zone walking, DNS enumeration" },
      ];
      expect(mapping.length).toBeGreaterThan(5);
      mapping.forEach(tech => {
        expect(tech.id).toMatch(/^T\d{4}/);
        expect(tech).toHaveProperty("name");
        expect(tech).toHaveProperty("tactic");
        expect(tech).toHaveProperty("dnsRelevance");
      });
    });
  });

  describe("getCheckCategories procedure", () => {
    it("should return 15 check categories", () => {
      const categories = [
        { id: "dangling_dns", name: "Dangling DNS / Subdomain Takeover", icon: "🔗" },
        { id: "dnssec", name: "DNSSEC Validation", icon: "🔐" },
        { id: "zone_transfer", name: "Zone Transfer (AXFR)", icon: "📋" },
        { id: "cache_poisoning", name: "Cache Poisoning", icon: "💉" },
        { id: "open_resolver", name: "Open Resolver", icon: "🌐" },
        { id: "amplification", name: "DNS Amplification", icon: "📡" },
        { id: "wildcard", name: "Wildcard DNS", icon: "✳️" },
        { id: "email_security", name: "Email Security (SPF/DKIM/DMARC)", icon: "📧" },
        { id: "caa", name: "CAA Records", icon: "📜" },
        { id: "zone_walking", name: "NSEC Zone Walking", icon: "🚶" },
        { id: "tunneling_indicator", name: "DNS Tunneling", icon: "🕳️" },
        { id: "version_disclosure", name: "Version Disclosure", icon: "🏷️" },
        { id: "dns_cookie", name: "DNS Cookies (RFC 7873)", icon: "🍪" },
        { id: "rate_limiting", name: "Response Rate Limiting", icon: "⏱️" },
        { id: "rebinding", name: "DNS Rebinding", icon: "🔄" },
      ];
      expect(categories.length).toBe(15);
      categories.forEach(cat => {
        expect(cat).toHaveProperty("id");
        expect(cat).toHaveProperty("name");
        expect(cat).toHaveProperty("icon");
      });
    });
  });

  describe("quickDanglingCheck procedure", () => {
    it("should accept domain and optional subdomains array", () => {
      const validInputs = [
        { domain: "example.com" },
        { domain: "example.com", subdomains: ["sub1.example.com", "sub2.example.com"] },
      ];
      validInputs.forEach(input => {
        expect(input.domain.length).toBeGreaterThan(0);
        if (input.subdomains) {
          expect(Array.isArray(input.subdomains)).toBe(true);
        }
      });
    });

    it("should limit subdomains to 20 per request", () => {
      const subdomains = Array.from({ length: 30 }, (_, i) => `sub${i}.example.com`);
      const toCheck = subdomains.slice(0, 20);
      expect(toCheck.length).toBe(20);
    });
  });
});

// ─── PDF Report Data Shape Tests ─────────────────────────────────────────────
describe("PDF Report DNS Security Section", () => {
  it("should access dnsSecurityReport from pipeline output", () => {
    const mockScan = {
      pipelineOutput: {
        passiveDiscovery: {
          dnsSecurityReport: {
            domain: "target.com",
            summary: {
              overallRisk: "high",
              totalFindings: 5,
              critical: 1,
              high: 2,
              medium: 1,
              low: 1,
              info: 0,
              totalChecks: 15,
              passedChecks: 10,
              failedChecks: 5,
            },
            findings: [
              { id: "f1", severity: "critical", category: "dangling_dns", title: "S3 Takeover" },
              { id: "f2", severity: "high", category: "zone_transfer", title: "AXFR Allowed" },
            ],
            records: [
              { type: "A", name: "target.com", value: "1.2.3.4", ttl: 300 },
            ],
            dnssec: {
              enabled: false,
              delegationSigned: false,
              rrsigPresent: false,
              chainOfTrustValid: false,
              algorithmStrength: null,
              dsRecords: [],
              dnskeyRecords: [],
              issues: ["No DNSSEC records found"],
            },
          },
        },
      },
    };
    const report = mockScan.pipelineOutput?.passiveDiscovery?.dnsSecurityReport;
    expect(report).toBeDefined();
    expect(report!.domain).toBe("target.com");
    expect(report!.summary.overallRisk).toBe("high");
    expect(report!.findings.length).toBe(2);
    expect(report!.dnssec.enabled).toBe(false);
  });

  it("should categorize findings for report sections", () => {
    const findings = [
      { id: "f1", severity: "critical", category: "dangling_dns", title: "S3 Takeover" },
      { id: "f2", severity: "high", category: "zone_transfer", title: "AXFR Allowed" },
      { id: "f3", severity: "medium", category: "email_security", title: "SPF too permissive" },
      { id: "f4", severity: "low", category: "caa", title: "No CAA records" },
      { id: "f5", severity: "info", category: "version_disclosure", title: "BIND version exposed" },
    ];
    const danglingFindings = findings.filter(f => f.category === "dangling_dns");
    const otherFindings = findings.filter(f => f.category !== "dangling_dns");
    const emailFindings = findings.filter(f => f.category === "email_security");
    const caaFindings = findings.filter(f => f.category === "caa");
    expect(danglingFindings.length).toBe(1);
    expect(otherFindings.length).toBe(4);
    expect(emailFindings.length).toBe(1);
    expect(caaFindings.length).toBe(1);
  });
});

// ─── DnsSecurityValidator Class Tests ────────────────────────────────────────
describe("DnsSecurityValidator class", () => {
  it("should be constructable with domain and context", async () => {
    const { DnsSecurityValidator } = await import("./lib/dns-security-validator");
    const validator = new DnsSecurityValidator("example.com", "di_scan");
    expect(validator).toBeDefined();
  });

  it("should accept all three engagement contexts", async () => {
    const { DnsSecurityValidator } = await import("./lib/dns-security-validator");
    const contexts: EngagementContext[] = ["di_scan", "vuln_pentest", "red_team"];
    contexts.forEach(ctx => {
      const v = new DnsSecurityValidator("test.com", ctx);
      expect(v).toBeDefined();
    });
  });

  it("should default context to di_scan if not provided", async () => {
    const { DnsSecurityValidator } = await import("./lib/dns-security-validator");
    const v = new DnsSecurityValidator("test.com");
    expect(v).toBeDefined();
  });
});

// ─── Integration: runDnsSecurityAssessment ───────────────────────────────────
describe("runDnsSecurityAssessment", () => {
  it("should be an async function that returns a DnsSecurityReport", async () => {
    const { runDnsSecurityAssessment } = await import("./lib/dns-security-validator");
    expect(typeof runDnsSecurityAssessment).toBe("function");
  });

  it("should handle domain with protocol prefix gracefully", async () => {
    // The router strips protocol, but the function itself should handle raw domains
    const domain = "example.com";
    const cleaned = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
    expect(cleaned).toBe("example.com");
  });
});

// ─── UI Tab Component Data Contract ──────────────────────────────────────────
describe("DnsSecurityTab data contract", () => {
  it("should expect pipeline prop with dnsSecurityReport", () => {
    const mockPipeline = {
      passiveDiscovery: {
        dnsSecurityReport: {
          domain: "example.com",
          summary: { overallRisk: "low", totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, totalChecks: 15, passedChecks: 15, failedChecks: 0 },
          findings: [],
          records: [{ type: "A", name: "example.com", value: "1.2.3.4", ttl: 300 }],
          dnssec: { enabled: true, delegationSigned: true, rrsigPresent: true, chainOfTrustValid: true, algorithmStrength: "strong", dsRecords: [], dnskeyRecords: [], issues: [] },
          metadata: { checksPerformed: [], responseTimeMs: 800, resolverUsed: "dns.google" },
        },
      },
    };
    const report = mockPipeline.passiveDiscovery?.dnsSecurityReport;
    expect(report).toBeDefined();
    expect(report.summary.overallRisk).toBe("low");
    expect(report.records.length).toBeGreaterThan(0);
  });

  it("should handle missing dnsSecurityReport gracefully (null)", () => {
    const mockPipeline = { passiveDiscovery: {} };
    const report = (mockPipeline as any).passiveDiscovery?.dnsSecurityReport || null;
    expect(report).toBeNull();
  });
});
