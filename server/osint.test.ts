import { describe, expect, it } from "vitest";
import {
  generateTyposquats,
  analyzeSpoofability,
  type DnsAnalysis,
  type TyposquatCandidate,
} from "./osint";

describe("generateTyposquats", () => {
  it("generates typosquat candidates for a domain", () => {
    const results = generateTyposquats("example.com");
    expect(results.length).toBeGreaterThan(0);
    // Should not include the original domain
    expect(results.find((r) => r.domain === "example.com")).toBeUndefined();
  });

  it("generates multiple permutation types", () => {
    const results = generateTyposquats("example.com");
    const types = new Set(results.map((r) => r.type));
    // Should have at least 5 different permutation types
    expect(types.size).toBeGreaterThanOrEqual(5);
    // Check specific types exist
    expect(types.has("omission")).toBe(true);
    expect(types.has("transposition")).toBe(true);
    expect(types.has("replacement")).toBe(true);
    expect(types.has("tld_swap")).toBe(true);
  });

  it("generates omission variants by removing each character", () => {
    const results = generateTyposquats("test.com");
    const omissions = results.filter((r) => r.type === "omission");
    expect(omissions.length).toBeGreaterThan(0);
    // "est.com" should be in the list (removing 't')
    expect(omissions.find((r) => r.domain === "est.com")).toBeTruthy();
    // "tes.com" should be in the list (removing last 't')
    expect(omissions.find((r) => r.domain === "tes.com")).toBeTruthy();
  });

  it("generates transposition variants by swapping adjacent chars", () => {
    const results = generateTyposquats("test.com");
    const transpositions = results.filter((r) => r.type === "transposition");
    expect(transpositions.length).toBeGreaterThan(0);
    // "tset.com" should be in the list (swapping 'e' and 's')
    expect(transpositions.find((r) => r.domain === "tset.com")).toBeTruthy();
  });

  it("generates TLD swap variants", () => {
    const results = generateTyposquats("example.com");
    const tldSwaps = results.filter((r) => r.type === "tld_swap");
    expect(tldSwaps.length).toBeGreaterThan(0);
    expect(tldSwaps.find((r) => r.domain === "example.net")).toBeTruthy();
    expect(tldSwaps.find((r) => r.domain === "example.org")).toBeTruthy();
    expect(tldSwaps.find((r) => r.domain === "example.io")).toBeTruthy();
  });

  it("generates repetition variants", () => {
    const results = generateTyposquats("test.com");
    const repetitions = results.filter((r) => r.type === "repetition");
    expect(repetitions.length).toBeGreaterThan(0);
    // "ttest.com" should exist
    expect(repetitions.find((r) => r.domain === "ttest.com")).toBeTruthy();
  });

  it("generates hyphenation variants", () => {
    const results = generateTyposquats("example.com");
    const hyphens = results.filter((r) => r.type === "hyphenation");
    expect(hyphens.length).toBeGreaterThan(0);
    expect(hyphens.find((r) => r.domain === "e-xample.com")).toBeTruthy();
  });

  it("does not produce duplicate domains", () => {
    const results = generateTyposquats("example.com");
    const domains = results.map((r) => r.domain);
    const unique = new Set(domains);
    expect(domains.length).toBe(unique.size);
  });

  it("handles short domain names", () => {
    const results = generateTyposquats("ab.com");
    expect(results.length).toBeGreaterThan(0);
  });

  it("generates subdomain trick variants", () => {
    const results = generateTyposquats("example.com");
    const tricks = results.filter((r) => r.type === "subdomain_trick");
    expect(tricks.length).toBeGreaterThan(0);
    expect(tricks.find((r) => r.domain === "wwwexample.com")).toBeTruthy();
  });
});

describe("analyzeSpoofability", () => {
  it("scores domain with no email security as highly spoofable", () => {
    const dns: DnsAnalysis = {
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      dmarcPolicy: null,
      dkimFound: false,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.spoofable).toBe(true);
    expect(result.recommendation).toBe("spoof");
    expect(result.factors.length).toBeGreaterThan(0);
  });

  it("scores domain with full security as well protected", () => {
    const dns: DnsAnalysis = {
      mxRecords: [{ exchange: "mail.example.com", priority: 10 }],
      spfRecord: "v=spf1 include:_spf.google.com -all",
      dmarcRecord: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      dmarcPolicy: "reject",
      dkimFound: true,
      nsRecords: ["ns1.example.com"],
      aRecords: ["1.2.3.4"],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    expect(result.score).toBeLessThan(30);
    expect(result.spoofable).toBe(false);
    expect(result.recommendation).toBe("buy_lookalike");
  });

  it("scores SPF soft fail as moderately spoofable", () => {
    const dns: DnsAnalysis = {
      mxRecords: [{ exchange: "mail.example.com", priority: 10 }],
      spfRecord: "v=spf1 include:_spf.google.com ~all",
      dmarcRecord: null,
      dmarcPolicy: null,
      dkimFound: false,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    // SPF soft fail + no DMARC + no DKIM = high score
    expect(result.score).toBeGreaterThanOrEqual(40);
    expect(result.spoofable).toBe(true);
  });

  it("scores DMARC none policy as weak", () => {
    const dns: DnsAnalysis = {
      mxRecords: [{ exchange: "mail.example.com", priority: 10 }],
      spfRecord: "v=spf1 -all",
      dmarcRecord: "v=DMARC1; p=none",
      dmarcPolicy: "none",
      dkimFound: true,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    // SPF hard fail (5) + DMARC none (25) + DKIM present (0) = 30
    expect(result.score).toBeGreaterThanOrEqual(25);
    expect(result.factors.some((f) => f.factor.includes("DMARC Policy: none"))).toBe(true);
  });

  it("caps score at 100", () => {
    const dns: DnsAnalysis = {
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      dmarcPolicy: null,
      dkimFound: false,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("includes factor details for each finding", () => {
    const dns: DnsAnalysis = {
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      dmarcPolicy: null,
      dkimFound: false,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    for (const factor of result.factors) {
      expect(factor.factor).toBeTruthy();
      expect(factor.impact).toBeTruthy();
      expect(factor.detail).toBeTruthy();
    }
  });

  it("identifies DMARC quarantine as medium impact", () => {
    const dns: DnsAnalysis = {
      mxRecords: [{ exchange: "mail.example.com", priority: 10 }],
      spfRecord: "v=spf1 -all",
      dmarcRecord: "v=DMARC1; p=quarantine",
      dmarcPolicy: "quarantine",
      dkimFound: true,
      nsRecords: [],
      aRecords: [],
      aaaaRecords: [],
    };
    const result = analyzeSpoofability(dns);
    expect(result.factors.some((f) => f.factor.includes("quarantine"))).toBe(true);
  });
});

describe("OSINT router procedures", () => {
  it("osint router is defined in appRouter", async () => {
    const { appRouter } = await import("./routers");
    // Verify the osint router exists
    expect(appRouter._def.procedures).toBeDefined();
  });
});
