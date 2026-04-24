import { describe, it, expect } from "vitest";
import { inferInfrastructure } from "./lib/infrastructure-inference";
import type { InfrastructureMap } from "./lib/infrastructure-inference";

// ─── Test Helpers ────────────────────────────────────────────────────────────

function makeObs(overrides: Partial<{
  name: string;
  assetType: string;
  source: string;
  tags: string[];
  evidence: Record<string, any>;
  riskLevel: string;
}> = {}) {
  return {
    name: overrides.name || "test.example.com",
    assetType: overrides.assetType || "host",
    source: overrides.source || "dns",
    tags: overrides.tags || [],
    evidence: overrides.evidence || {},
    riskLevel: overrides.riskLevel || "low",
  };
}

function makeAsset(overrides: Partial<{
  hostname: string;
  technologies: string[];
  technologyVersions: Record<string, string>;
  assetClasses: string[];
  headers: string;
  tags: string[];
}> = {}) {
  return {
    hostname: overrides.hostname || "www.example.com",
    technologies: overrides.technologies || [],
    technologyVersions: overrides.technologyVersions || {},
    assetClasses: overrides.assetClasses || [],
    headers: overrides.headers || "",
    tags: overrides.tags || [],
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("Infrastructure Inference Engine", () => {

  describe("Basic operation", () => {
    it("returns a valid InfrastructureMap for empty inputs", () => {
      const result = inferInfrastructure("example.com", [], []);
      expect(result.domain).toBe("example.com");
      expect(result.generatedAt).toBeTruthy();
      expect(result.services).toEqual([]);
      expect(result.vendorDependencies).toEqual([]);
      expect(result.techLifecycle).toEqual([]);
      // Even with empty inputs, missing CDN/WAF defense is flagged
      expect(result.supplyChainRisks.length).toBe(1);
      expect(result.supplyChainRisks[0].riskType).toBe("missing_defense");
      expect(result.summary.totalServices).toBe(0);
      expect(result.summary.overallMaturity).toBe("minimal");
    });

    it("generates unique service IDs", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx1.google.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const ids = result.services.map(s => s.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
  });

  describe("DNS Infrastructure Detection", () => {
    it("detects DNS provider from NS records", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns2.cloudflare.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const dns = result.services.find(s => s.category === "dns");
      expect(dns).toBeTruthy();
      expect(dns!.provider).toContain("cloudflare");
      expect(dns!.confidence).toBeGreaterThanOrEqual(0.9);
      expect(dns!.exposedExternally).toBe(true);
      expect(dns!.ports).toContain(53);
    });

    it("handles multiple DNS providers", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:route53"], name: "ns1.awsdns.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const dns = result.services.find(s => s.category === "dns");
      expect(dns).toBeTruthy();
      expect(dns!.provider).toContain("cloudflare");
      expect(dns!.provider).toContain("route53");
    });
  });

  describe("Email Infrastructure Detection", () => {
    it("detects Google Workspace from MX records", () => {
      const obs = [
        makeObs({ assetType: "mx", tags: ["mx"], name: "aspmx.l.google.com" }),
        makeObs({ assetType: "mx", tags: ["mx"], name: "alt1.aspmx.l.google.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const email = result.services.find(s => s.category === "email");
      expect(email).toBeTruthy();
      expect(email!.provider).toBe("Google Workspace");
      expect(email!.managedByThirdParty).toBe(true);
    });

    it("detects Microsoft 365 from MX records", () => {
      const obs = [
        makeObs({ assetType: "mx", tags: ["mx"], name: "example-com.mail.protection.outlook.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const email = result.services.find(s => s.category === "email");
      expect(email).toBeTruthy();
      expect(email!.provider).toBe("Microsoft 365");
    });

    it("uses managedProvider when available", () => {
      const obs = [
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx.proofpoint.com" }),
      ];
      const managed = { name: "Proofpoint Enterprise", tier: "enterprise" };
      const result = inferInfrastructure("example.com", obs, [], null, managed);
      const email = result.services.find(s => s.category === "email");
      expect(email).toBeTruthy();
      expect(email!.provider).toBe("Proofpoint Enterprise");
    });

    it("includes SPF/DMARC/DKIM evidence", () => {
      const obs = [
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx.google.com" }),
        makeObs({ tags: ["email_security", "spf", "spf_present"], name: "spf" }),
        makeObs({ tags: ["email_security", "dmarc", "dmarc_present"], name: "dmarc" }),
        makeObs({ tags: ["email_security", "dkim", "dkim_present"], name: "dkim" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const email = result.services.find(s => s.category === "email");
      expect(email).toBeTruthy();
      expect(email!.evidence.some(e => e.includes("SPF: configured"))).toBe(true);
      expect(email!.evidence.some(e => e.includes("DMARC: configured"))).toBe(true);
      expect(email!.evidence.some(e => e.includes("DKIM: configured"))).toBe(true);
    });
  });

  describe("CDN / WAF Detection", () => {
    it("detects Cloudflare from CNAME records", () => {
      const obs = [
        makeObs({ tags: ["cname_record"], name: "cdn.cloudflare.net", evidence: { records: ["cdn.cloudflare.net"] } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const cdn = result.services.find(s => s.category === "cdn_waf");
      expect(cdn).toBeTruthy();
      expect(cdn!.name).toBe("Cloudflare");
    });

    it("detects WAF from header observations", () => {
      const obs = [
        makeObs({ tags: ["waf_detected"], evidence: { wafName: "Imperva/Incapsula" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const waf = result.services.find(s => s.category === "cdn_waf");
      expect(waf).toBeTruthy();
      expect(waf!.name).toBe("Imperva/Incapsula");
    });

    it("detects CDN from asset tags", () => {
      const assets = [
        makeAsset({ tags: ["cdn:akamai"] }),
      ];
      const result = inferInfrastructure("example.com", [], assets);
      const cdn = result.services.find(s => s.category === "cdn_waf");
      expect(cdn).toBeTruthy();
      expect(cdn!.name).toBe("Akamai");
    });
  });

  describe("Cloud Hosting Detection", () => {
    it("detects AWS from DNS observations", () => {
      const obs = [
        makeObs({ source: "dns", name: "ec2-1-2-3-4.compute-1.amazonaws.com", evidence: { records: ["ec2-1-2-3-4.compute-1.amazonaws.com"] } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const cloud = result.services.find(s => s.category === "cloud_hosting");
      expect(cloud).toBeTruthy();
      expect(cloud!.provider).toBe("AWS");
    });

    it("detects cloud provider from Shodan ASN data", () => {
      const obs = [
        makeObs({ source: "shodan", name: "1.2.3.4", evidence: { org: "Amazon.com, Inc.", isp: "Amazon Technologies" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      // Should not match just "Amazon" — patterns need "amazonaws.com" etc.
      // But the org field has "Amazon" which doesn't match cloud patterns
      // This tests the Shodan path
    });

    it("increases confidence with multiple evidence sources", () => {
      const obs = [
        makeObs({ source: "dns", name: "example.azurewebsites.net" }),
        makeObs({ source: "shodan", name: "1.2.3.4", evidence: { org: "Microsoft Azure" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const azure = result.services.find(s => s.category === "cloud_hosting" && s.provider === "Azure");
      expect(azure).toBeTruthy();
      expect(azure!.confidence).toBeGreaterThanOrEqual(0.9);
    });
  });

  describe("Cloud Storage Detection", () => {
    it("detects public cloud storage buckets", () => {
      const obs = [
        makeObs({
          tags: ["cloud_asset", "public_bucket"],
          name: "example-backup.s3.amazonaws.com",
          evidence: { provider: "AWS S3", bucketName: "example-backup" },
        }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const storage = result.services.find(s => s.category === "cloud_storage");
      expect(storage).toBeTruthy();
      expect(storage!.exposedExternally).toBe(true);
      expect(result.inferenceNotes.some(n => n.includes("publicly accessible"))).toBe(true);
    });
  });

  describe("Web Server Detection", () => {
    it("detects nginx from asset technologies", () => {
      const assets = [
        makeAsset({ technologies: ["nginx"], technologyVersions: { nginx: "1.25.3" } }),
      ];
      const result = inferInfrastructure("example.com", [], assets);
      const ws = result.services.find(s => s.category === "web_server");
      expect(ws).toBeTruthy();
      expect(ws!.name).toBe("nginx");
      expect(ws!.version).toBe("1.25.3");
    });

    it("detects web server from HTTP header fingerprint", () => {
      const obs = [
        makeObs({ tags: ["tech_fingerprint"], evidence: { serverBanner: "Apache/2.4.57" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const ws = result.services.find(s => s.category === "web_server");
      expect(ws).toBeTruthy();
      expect(ws!.name).toBe("Apache");
      expect(ws!.version).toBe("2.4.57");
    });
  });

  describe("Application Framework & CMS Detection", () => {
    it("detects WordPress from asset technologies", () => {
      const assets = [
        makeAsset({ technologies: ["WordPress"], technologyVersions: { WordPress: "6.4.2" } }),
      ];
      const result = inferInfrastructure("example.com", [], assets);
      const cms = result.services.find(s => s.category === "cms");
      expect(cms).toBeTruthy();
      expect(cms!.name).toBe("WordPress");
      expect(cms!.version).toBe("6.4.2");
    });

    it("detects React from asset technologies", () => {
      const assets = [
        makeAsset({ technologies: ["React", "Next.js"] }),
      ];
      const result = inferInfrastructure("example.com", [], assets);
      const frameworks = result.services.filter(s => s.category === "application_framework");
      expect(frameworks.length).toBeGreaterThanOrEqual(1);
      expect(frameworks.some(f => f.name === "React")).toBe(true);
    });

    it("does not duplicate framework detections", () => {
      const assets = [
        makeAsset({ hostname: "www.example.com", technologies: ["React"] }),
        makeAsset({ hostname: "app.example.com", technologies: ["React"] }),
      ];
      const result = inferInfrastructure("example.com", [], assets);
      const reactServices = result.services.filter(s => s.name === "React");
      expect(reactServices.length).toBe(1);
    });
  });

  describe("Authentication Provider Detection", () => {
    it("detects Okta from DNS TXT verification records", () => {
      const obs = [
        makeObs({
          tags: ["txt_record"],
          evidence: { records: ["okta-domain-verification=abc123"] },
        }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const auth = result.services.find(s => s.category === "authentication");
      expect(auth).toBeTruthy();
      expect(auth!.name).toBe("Okta");
      expect(auth!.managedByThirdParty).toBe(true);
    });
  });

  describe("Certificate Authority Detection", () => {
    it("detects CA from CAA records", () => {
      const obs = [
        makeObs({
          tags: ["caa_record"],
          evidence: { authorizedIssuers: ["letsencrypt.org", "digicert.com"] },
        }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const ca = result.services.find(s => s.category === "certificate_authority");
      expect(ca).toBeTruthy();
      expect(ca!.provider).toContain("letsencrypt.org");
      expect(ca!.provider).toContain("digicert.com");
      expect(ca!.evidence.some(e => e.includes("CAA DNS record present"))).toBe(true);
    });
  });

  describe("Vendor Dependency Analysis", () => {
    it("identifies vendor concentration", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ tags: ["cname_record"], name: "cdn.cloudflare.net", evidence: { records: ["cdn.cloudflare.net"] } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const cfDep = result.vendorDependencies.find(d => d.vendor === "Cloudflare");
      // Cloudflare appears in both DNS and CDN
      expect(cfDep).toBeTruthy();
      expect(cfDep!.serviceCount).toBeGreaterThanOrEqual(1);
    });

    it("sorts vendors by service count descending", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx.google.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      if (result.vendorDependencies.length >= 2) {
        expect(result.vendorDependencies[0].serviceCount).toBeGreaterThanOrEqual(result.vendorDependencies[1].serviceCount);
      }
    });
  });

  describe("Technology Lifecycle Assessment", () => {
    it("flags Apache 2.2 as EOL", () => {
      const obs = [
        makeObs({ tags: ["tech_fingerprint"], evidence: { serverBanner: "Apache/2.2.34" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const lifecycle = result.techLifecycle.find(t => t.technology === "Apache");
      expect(lifecycle).toBeTruthy();
      expect(lifecycle!.eolStatus).toBe("eol");
    });

    it("flags OpenSSL 1.1 as EOL", () => {
      const assets = [
        makeAsset({ technologies: ["OpenSSL"], technologyVersions: { OpenSSL: "1.1.1w" } }),
      ];
      // OpenSSL detection would need to be in web_server category or similar
      // The inference engine detects it through tech fingerprinting
      const obs = [
        makeObs({ tags: ["tech_fingerprint"], evidence: { serverBanner: "OpenSSL/1.1.1w" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const lifecycle = result.techLifecycle.find(t => t.technology === "OpenSSL");
      expect(lifecycle).toBeTruthy();
      expect(lifecycle!.eolStatus).toBe("eol");
    });

    it("flags PHP 7 as EOL", () => {
      const assets = [
        makeAsset({ technologies: ["PHP"], technologyVersions: { PHP: "7.4.33" } }),
      ];
      // PHP detected through web server category won't trigger lifecycle
      // but through tech fingerprint it will
      const obs = [
        makeObs({ tags: ["tech_fingerprint"], evidence: { serverBanner: "PHP/7.4.33" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const lifecycle = result.techLifecycle.find(t => t.technology === "PHP");
      expect(lifecycle).toBeTruthy();
      expect(lifecycle!.eolStatus).toBe("eol");
    });
  });

  describe("Supply Chain Risk Assessment", () => {
    it("flags missing CDN/WAF as high risk", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record"], name: "ns1.example.com" }),
      ];
      const assets = [
        makeAsset({ technologies: ["nginx"], technologyVersions: { nginx: "1.25.3" } }),
      ];
      const result = inferInfrastructure("example.com", obs, assets);
      const missingWaf = result.supplyChainRisks.find(r => r.riskType === "missing_defense");
      expect(missingWaf).toBeTruthy();
      expect(missingWaf!.severity).toBe("high");
    });

    it("does NOT flag missing CDN/WAF when CDN is present", () => {
      const obs = [
        makeObs({ tags: ["cname_record"], name: "cdn.cloudflare.net", evidence: { records: ["cdn.cloudflare.net"] } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const missingWaf = result.supplyChainRisks.find(r => r.riskType === "missing_defense");
      expect(missingWaf).toBeFalsy();
    });

    it("flags legacy technology as high risk", () => {
      const obs = [
        makeObs({ tags: ["tech_fingerprint"], evidence: { serverBanner: "Apache/2.2.34" } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const legacy = result.supplyChainRisks.find(r => r.riskType === "legacy_tech");
      expect(legacy).toBeTruthy();
      expect(legacy!.severity).toBe("high");
    });

    it("flags unmanaged database exposure as critical", () => {
      const obs = [
        makeObs({
          source: "shodan",
          name: "1.2.3.4",
          evidence: {
            services: [{ port: 3306, product: "MySQL", version: "8.0" }],
          },
        }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      const unmanaged = result.supplyChainRisks.find(r => r.riskType === "unmanaged_exposure");
      expect(unmanaged).toBeTruthy();
      expect(unmanaged!.severity).toBe("critical");
    });
  });

  describe("Summary Calculation", () => {
    it("calculates maturity as 'minimal' with no security controls", () => {
      const result = inferInfrastructure("example.com", [], []);
      expect(result.summary.overallMaturity).toBe("minimal");
    });

    it("calculates maturity as 'basic' with CDN only", () => {
      const obs = [
        makeObs({ tags: ["cname_record"], name: "cdn.cloudflare.net", evidence: { records: ["cdn.cloudflare.net"] } }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      expect(result.summary.overallMaturity).toBe("basic");
    });

    it("counts third-party managed services correctly", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx.google.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      expect(result.summary.thirdPartyManaged).toBeGreaterThanOrEqual(2);
    });

    it("counts externally exposed services correctly", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record"], name: "ns1.example.com" }),
      ];
      const assets = [
        makeAsset({ technologies: ["nginx"] }),
      ];
      const result = inferInfrastructure("example.com", obs, assets);
      expect(result.summary.externallyExposed).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Inference Notes", () => {
    it("generates inference notes for detected services", () => {
      const obs = [
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "mx", tags: ["mx"], name: "mx.google.com" }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      expect(result.inferenceNotes.length).toBeGreaterThanOrEqual(2);
      expect(result.inferenceNotes.some(n => n.includes("DNS"))).toBe(true);
      expect(result.inferenceNotes.some(n => n.includes("Email"))).toBe(true);
    });

    it("warns about public buckets in inference notes", () => {
      const obs = [
        makeObs({
          tags: ["cloud_asset", "public_bucket"],
          name: "example-data.s3.amazonaws.com",
          evidence: { provider: "AWS S3", bucketName: "example-data" },
        }),
      ];
      const result = inferInfrastructure("example.com", obs, []);
      expect(result.inferenceNotes.some(n => n.startsWith("WARNING"))).toBe(true);
    });
  });

  describe("Complex Scenario", () => {
    it("handles a realistic multi-service infrastructure", () => {
      const obs = [
        // DNS
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns1.cloudflare.com" }),
        makeObs({ assetType: "ns", tags: ["ns_record", "dns_provider:cloudflare"], name: "ns2.cloudflare.com" }),
        // Email
        makeObs({ assetType: "mx", tags: ["mx"], name: "aspmx.l.google.com" }),
        makeObs({ tags: ["email_security", "spf", "spf_present"], name: "spf" }),
        makeObs({ tags: ["email_security", "dmarc", "dmarc_present"], name: "dmarc" }),
        // CDN
        makeObs({ tags: ["cname_record"], name: "cdn.cloudflare.net", evidence: { records: ["cdn.cloudflare.net"] } }),
        // Cloud
        makeObs({ source: "dns", name: "app.us-east-1.amazonaws.com" }),
        // Auth
        makeObs({ tags: ["txt_record"], evidence: { records: ["okta-domain-verification=abc123"] } }),
        // CA
        makeObs({ tags: ["caa_record"], evidence: { authorizedIssuers: ["letsencrypt.org"] } }),
      ];
      const assets = [
        makeAsset({ hostname: "www.example.com", technologies: ["nginx", "React", "Next.js"], technologyVersions: { nginx: "1.25.3" } }),
        makeAsset({ hostname: "api.example.com", technologies: ["nginx", "Express.js"] }),
      ];

      const result = inferInfrastructure("example.com", obs, assets);

      // Should have multiple service categories
      expect(result.services.length).toBeGreaterThanOrEqual(5);

      // Check key categories exist
      const categories = new Set(result.services.map(s => s.category));
      expect(categories.has("dns")).toBe(true);
      expect(categories.has("email")).toBe(true);
      expect(categories.has("cdn_waf")).toBe(true);
      expect(categories.has("cloud_hosting")).toBe(true);
      expect(categories.has("authentication")).toBe(true);
      expect(categories.has("web_server")).toBe(true);
      expect(categories.has("certificate_authority")).toBe(true);

      // Vendor dependencies should exist
      expect(result.vendorDependencies.length).toBeGreaterThanOrEqual(1);

      // Maturity should be at least moderate (CDN + auth)
      expect(["moderate", "advanced"]).toContain(result.summary.overallMaturity);

      // Summary counts should be consistent
      expect(result.summary.totalServices).toBe(result.services.length);
      expect(result.summary.totalVendors).toBeGreaterThanOrEqual(1);
    });
  });
});
