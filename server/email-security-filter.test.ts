/**
 * Tests for SPF/DKIM finding suppression when domain has no MX records.
 *
 * The key rule: if a domain has no MX records (i.e. it is not a mail server),
 * then missing SPF and DKIM should NOT be reported as posture findings.
 * DMARC findings should still be reported (anti-spoofing is always relevant).
 */
import { describe, it, expect } from "vitest";
import { generateEmailPostureFindings, type EmailSecurityReport } from "./lib/email-security-analyzer";

function makeReport(overrides: Partial<EmailSecurityReport> = {}): EmailSecurityReport {
  return {
    domain: "example.com",
    analyzedAt: new Date().toISOString(),
    overallScore: 20,
    overallGrade: "F",
    totalWeaknesses: 3,
    criticalWeaknesses: 1,
    phishingDifficultyRating: "trivial",
    phishingSummary: "Email security is critically weak.",
    recommendations: [],
    spf: {
      exists: false,
      record: null,
      allMechanism: null,
      score: 0,
      lookupCount: 0,
      includes: [],
      ipRanges: [],
      weaknesses: [
        {
          id: "spf-missing",
          severity: "critical",
          title: "No SPF Record",
          description: "Domain has no SPF record.",
          phishingRelevance: "Any server can send as this domain.",
        },
      ],
    },
    dkim: {
      selectorsFound: [],
      selectorResults: [],
      score: 0,
      weaknesses: [
        {
          id: "dkim-none-found",
          severity: "high",
          title: "No DKIM Selectors Found",
          description: "No DKIM selectors found.",
          phishingRelevance: "Email authenticity cannot be verified.",
        },
      ],
    },
    dmarc: {
      exists: false,
      record: null,
      policy: null,
      subdomainPolicy: null,
      percentage: 100,
      reportingEnabled: false,
      score: 0,
      weaknesses: [
        {
          id: "dmarc-missing",
          severity: "high",
          title: "No DMARC Record",
          description: "Domain has no DMARC policy.",
          phishingRelevance: "No enforcement on authentication failures.",
        },
      ],
    },
    mx: {
      records: [],
      provider: null,
      supportsStartTls: null,
      weaknesses: [
        {
          id: "mx-none",
          severity: "medium",
          title: "No MX Records Found",
          description: "Domain has no MX records.",
          phishingRelevance: "Domain may not receive email.",
        },
      ],
    },
    ...overrides,
  } as EmailSecurityReport;
}

describe("generateEmailPostureFindings — mail server filtering", () => {
  it("suppresses SPF and DKIM findings when domain has NO MX records", () => {
    const report = makeReport(); // no MX records
    const findings = generateEmailPostureFindings("example.com", report);

    const spfFindings = findings.filter((f) => f.category.includes("SPF"));
    const dkimFindings = findings.filter((f) => f.category.includes("DKIM"));

    expect(spfFindings).toHaveLength(0);
    expect(dkimFindings).toHaveLength(0);
  });

  it("still reports DMARC findings even when domain has no MX records", () => {
    const report = makeReport(); // no MX records
    const findings = generateEmailPostureFindings("example.com", report);

    const dmarcFindings = findings.filter((f) => f.category.includes("DMARC"));
    expect(dmarcFindings.length).toBeGreaterThan(0);
    expect(dmarcFindings[0].title).toBe("No DMARC Record");
  });

  it("still reports MX findings when domain has no MX records", () => {
    const report = makeReport(); // no MX records
    const findings = generateEmailPostureFindings("example.com", report);

    const mxFindings = findings.filter((f) => f.category.includes("MX"));
    expect(mxFindings.length).toBeGreaterThan(0);
  });

  it("includes SPF and DKIM findings when domain HAS MX records (is a mail server)", () => {
    const report = makeReport({
      mx: {
        records: [{ priority: 10, exchange: "mail.example.com" }],
        provider: null,
        supportsStartTls: null,
        weaknesses: [],
      },
    });
    const findings = generateEmailPostureFindings("example.com", report);

    const spfFindings = findings.filter((f) => f.category.includes("SPF"));
    const dkimFindings = findings.filter((f) => f.category.includes("DKIM"));

    expect(spfFindings.length).toBeGreaterThan(0);
    expect(dkimFindings.length).toBeGreaterThan(0);
  });

  it("returns no SPF/DKIM findings for a non-mail domain even with multiple weaknesses", () => {
    const report = makeReport({
      spf: {
        exists: false,
        record: null,
        allMechanism: null,
        score: 0,
        lookupCount: 0,
        includes: [],
        ipRanges: [],
        weaknesses: [
          { id: "spf-missing", severity: "critical", title: "No SPF Record", description: "...", phishingRelevance: "..." },
          { id: "spf-no-all", severity: "medium", title: "SPF No All", description: "...", phishingRelevance: "..." },
        ],
      } as any,
      dkim: {
        selectorsFound: [],
        selectorResults: [],
        score: 0,
        weaknesses: [
          { id: "dkim-none-found", severity: "high", title: "No DKIM", description: "...", phishingRelevance: "..." },
          { id: "dkim-weak-key", severity: "medium", title: "Weak Key", description: "...", phishingRelevance: "..." },
        ],
      } as any,
    });
    const findings = generateEmailPostureFindings("example.com", report);

    const spfFindings = findings.filter((f) => f.category.includes("SPF"));
    const dkimFindings = findings.filter((f) => f.category.includes("DKIM"));

    expect(spfFindings).toHaveLength(0);
    expect(dkimFindings).toHaveLength(0);
  });

  it("correctly counts total findings with mail infra present vs absent", () => {
    // Without mail infra: only DMARC + MX findings
    const noMailReport = makeReport();
    const noMailFindings = generateEmailPostureFindings("example.com", noMailReport);

    // With mail infra: SPF + DKIM + DMARC + MX findings
    const withMailReport = makeReport({
      mx: {
        records: [{ priority: 10, exchange: "mail.example.com" }],
        provider: "Google Workspace",
        supportsStartTls: true,
        weaknesses: [],
      },
    });
    const withMailFindings = generateEmailPostureFindings("example.com", withMailReport);

    // With mail infra should have MORE findings (SPF + DKIM added)
    expect(withMailFindings.length).toBeGreaterThan(noMailFindings.length);
  });
});
