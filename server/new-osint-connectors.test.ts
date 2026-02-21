import { describe, it, expect } from "vitest";
import { emailSecurityConnector } from "./lib/passive/email-security";
import { httpSecurityConnector } from "./lib/passive/http-security";
import { cloudAssetsConnector } from "./lib/passive/cloud-assets";
import { dnsDeepConnector } from "./lib/passive/dns-deep";

describe("Email Security Connector", () => {
  it("has correct connector metadata", () => {
    expect(emailSecurityConnector.name).toBe("email_security");
    expect(emailSecurityConnector.requiresApiKey).toBe(false);
  });

  it("collects email security observations for a real domain", async () => {
    const result = await emailSecurityConnector.collect("google.com", { timeout: 15000 });
    expect(result.connector).toBe("email_security");
    expect(result.domain).toBe("google.com");
    expect(result.observations.length).toBeGreaterThan(0);
    // Google should have SPF
    const spfObs = result.observations.find(o => o.tags.includes("spf"));
    expect(spfObs).toBeDefined();
    expect(spfObs!.tags).toContain("spf_present");
    // Google should have DMARC
    const dmarcObs = result.observations.find(o => o.tags.includes("dmarc"));
    expect(dmarcObs).toBeDefined();
    expect(dmarcObs!.tags).toContain("dmarc_present");
    // Google should have MX records
    const mxObs = result.observations.find(o => o.tags.includes("mx"));
    expect(mxObs).toBeDefined();
  }, 30000);

  it("handles non-existent domain gracefully", async () => {
    const result = await emailSecurityConnector.collect("this-domain-definitely-does-not-exist-xyz123.com", { timeout: 5000 });
    expect(result.errors.length).toBe(0); // DNS failures are handled gracefully
    // SPF and DMARC should show as missing
    const spfObs = result.observations.find(o => o.tags.includes("spf"));
    expect(spfObs).toBeDefined();
    expect(spfObs!.tags).toContain("spf_missing");
  }, 15000);
});

describe("HTTP Security Connector", () => {
  it("has correct connector metadata", () => {
    expect(httpSecurityConnector.name).toBe("http_security");
    expect(httpSecurityConnector.requiresApiKey).toBe(false);
  });

  it("detects security headers on a real domain", async () => {
    const result = await httpSecurityConnector.collect("google.com", { timeout: 15000 });
    expect(result.connector).toBe("http_security");
    expect(result.observations.length).toBeGreaterThan(0);
    // Should have security headers observation
    const headersObs = result.observations.find(o => o.tags.includes("security_headers"));
    expect(headersObs).toBeDefined();
    expect(headersObs!.evidence.securityHeaders).toBeDefined();
    expect(headersObs!.evidence.securityHeaders.length).toBeGreaterThan(0);
  }, 30000);
});

describe("Cloud Assets Connector", () => {
  it("has correct connector metadata", () => {
    expect(cloudAssetsConnector.name).toBe("cloud_assets");
    expect(cloudAssetsConnector.requiresApiKey).toBe(false);
  });

  it("generates and probes cloud storage candidates", async () => {
    const result = await cloudAssetsConnector.collect("example.com", { timeout: 5000 });
    expect(result.connector).toBe("cloud_assets");
    expect(result.domain).toBe("example.com");
    // Should always have at least the summary observation
    const summaryObs = result.observations.find(o => o.tags.includes("cloud_summary"));
    expect(summaryObs).toBeDefined();
    expect(summaryObs!.evidence.totalProbed).toBeGreaterThan(0);
  }, 120000);
});

describe("DNS Deep Connector", () => {
  it("has correct connector metadata", () => {
    expect(dnsDeepConnector.name).toBe("dns_deep");
    expect(dnsDeepConnector.requiresApiKey).toBe(false);
  });

  it("collects comprehensive DNS records for a real domain", async () => {
    const result = await dnsDeepConnector.collect("google.com");
    expect(result.connector).toBe("dns_deep");
    expect(result.observations.length).toBeGreaterThan(0);
    // Google should have A records
    const aObs = result.observations.find(o => o.tags.includes("a_record"));
    expect(aObs).toBeDefined();
    // Google should have NS records
    const nsObs = result.observations.find(o => o.tags.includes("ns_record"));
    expect(nsObs).toBeDefined();
    // Google should have SOA record
    const soaObs = result.observations.find(o => o.tags.includes("soa_record"));
    expect(soaObs).toBeDefined();
  }, 30000);
});
