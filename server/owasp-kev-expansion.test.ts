import { describe, it, expect, vi } from "vitest";

// ─── OWASP Knowledge Module Tests ───────────────────────────────────────────

describe("OWASP Knowledge Module", () => {
  it("should export all required context functions", async () => {
    const mod = await import("./lib/owasp-knowledge");
    expect(typeof mod.getOwaspScanPlanContext).toBe("function");
    expect(typeof mod.getOwaspVulnCorrelationContext).toBe("function");
    expect(typeof mod.getOwaspAssetClassificationContext).toBe("function");
    expect(typeof mod.getOwaspHuntContext).toBe("function");
  });

  it("getOwaspScanPlanContext returns tech-specific tool recommendations", async () => {
    const { getOwaspScanPlanContext } = await import("./lib/owasp-knowledge");
    const ctx = getOwaspScanPlanContext(["php", "mysql", "nginx"]);
    expect(ctx).toContain("OWASP");
    expect(ctx.length).toBeGreaterThan(100);
    // Should mention injection testing for PHP/MySQL
    expect(ctx.toLowerCase()).toMatch(/injection|sql/);
  });

  it("getOwaspScanPlanContext returns generic context with no tech", async () => {
    const { getOwaspScanPlanContext } = await import("./lib/owasp-knowledge");
    const ctx = getOwaspScanPlanContext([]);
    expect(ctx).toContain("OWASP");
    expect(ctx.length).toBeGreaterThan(50);
  });

  it("getOwaspVulnCorrelationContext returns OWASP classification guidance", async () => {
    const { getOwaspVulnCorrelationContext } = await import("./lib/owasp-knowledge");
    const ctx = getOwaspVulnCorrelationContext();
    expect(ctx).toContain("OWASP");
    expect(ctx).toContain("A01");
    expect(ctx).toContain("A03");
    expect(ctx).toContain("A10");
  });

  it("getOwaspAssetClassificationContext returns risk multipliers", async () => {
    const { getOwaspAssetClassificationContext } = await import("./lib/owasp-knowledge");
    const ctx = getOwaspAssetClassificationContext();
    expect(ctx).toContain("OWASP");
    expect(ctx.toLowerCase()).toMatch(/risk|exposure|attack surface/);
  });

  it("getOwaspHuntContext returns MITRE-mapped detection guidance", async () => {
    const { getOwaspHuntContext } = await import("./lib/owasp-knowledge");
    const ctx = getOwaspHuntContext();
    expect(ctx).toContain("OWASP");
    expect(ctx).toMatch(/T1\d{3,4}/); // MITRE technique IDs
  });
});

// ─── Expanded KEV Catalog Tests ─────────────────────────────────────────────

describe("Expanded KEV TECH_TO_KEV_PATTERNS", () => {
  it("should include cloud and container technologies", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["kubernetes"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["docker"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["aws"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["terraform"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["vault"]).toBeDefined();
  });

  it("should include CI/CD technologies", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["github"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["teamcity"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["harbor"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["nexus"]).toBeDefined();
  });

  it("should include modern web frameworks", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["node.js"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["django"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["laravel"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["rails"]).toBeDefined();
  });

  it("should include API gateways and proxies", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["kong"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["envoy"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["traefik"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["haproxy"]).toBeDefined();
  });

  it("should include message queues and data stores", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["redis"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["kafka"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["elasticsearch"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["mongodb"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["grafana"]).toBeDefined();
  });

  it("should include expanded identity providers", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["keycloak"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["adfs"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["ivanti"]).toBeDefined();
  });

  it("should include file transfer and collaboration tools", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    expect(TECH_TO_KEV_PATTERNS["goanywhere"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["nextcloud"]).toBeDefined();
    expect(TECH_TO_KEV_PATTERNS["mattermost"]).toBeDefined();
  });

  it("should have at least 110 technology patterns", async () => {
    const { TECH_TO_KEV_PATTERNS } = await import("./lib/kev-service");
    const count = Object.keys(TECH_TO_KEV_PATTERNS).length;
    expect(count).toBeGreaterThanOrEqual(110);
  });
});

// ─── KEV OWASP Classification Tests ────────────────────────────────────────

describe("KEV OWASP Classification", () => {
  it("classifyKevByOwasp should classify injection vulnerabilities", async () => {
    const { classifyKevByOwasp } = await import("./lib/kev-service");
    const entry = {
      cveID: "CVE-2021-44228",
      vendorProject: "Apache",
      product: "Log4j",
      vulnerabilityName: "Apache Log4j Remote Code Execution Vulnerability",
      shortDescription: "Apache Log4j2 allows remote code execution via JNDI injection in log messages",
      dateAdded: "2021-12-10",
      dueDate: "2021-12-24",
      requiredAction: "Apply updates per vendor instructions",
      knownRansomwareCampaignUse: "Known",
    };
    const cats = classifyKevByOwasp(entry as any);
    expect(cats).toContain("A03:2025-Injection");
    expect(cats).toContain("A06:2025-Vulnerable_Outdated_Components");
  });

  it("classifyKevByOwasp should classify auth bypass as A01", async () => {
    const { classifyKevByOwasp } = await import("./lib/kev-service");
    const entry = {
      cveID: "CVE-2023-46747",
      vendorProject: "F5",
      product: "BIG-IP",
      vulnerabilityName: "F5 BIG-IP Authentication Bypass Vulnerability",
      shortDescription: "F5 BIG-IP allows authentication bypass via undisclosed requests",
      dateAdded: "2023-10-31",
      dueDate: "2023-11-21",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const cats = classifyKevByOwasp(entry as any);
    expect(cats).toContain("A01:2025-Broken_Access_Control");
  });

  it("classifyKevByOwasp should classify SSRF as A10", async () => {
    const { classifyKevByOwasp } = await import("./lib/kev-service");
    const entry = {
      cveID: "CVE-2021-26855",
      vendorProject: "Microsoft",
      product: "Exchange Server",
      vulnerabilityName: "Microsoft Exchange Server SSRF Vulnerability",
      shortDescription: "Microsoft Exchange Server contains a server-side request forgery vulnerability",
      dateAdded: "2021-03-03",
      dueDate: "2021-03-17",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const cats = classifyKevByOwasp(entry as any);
    expect(cats).toContain("A10:2025-SSRF");
  });

  it("classifyKevByOwasp should always include A06 for all KEV entries", async () => {
    const { classifyKevByOwasp } = await import("./lib/kev-service");
    const entry = {
      cveID: "CVE-2024-0001",
      vendorProject: "Test",
      product: "Test",
      vulnerabilityName: "Test Vulnerability",
      shortDescription: "A generic vulnerability with no specific keywords",
      dateAdded: "2024-01-01",
      dueDate: "2024-01-15",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const cats = classifyKevByOwasp(entry as any);
    expect(cats).toContain("A06:2025-Vulnerable_Outdated_Components");
  });

  it("classifyKevByOwasp should classify deserialization as A08", async () => {
    const { classifyKevByOwasp } = await import("./lib/kev-service");
    const entry = {
      cveID: "CVE-2023-34362",
      vendorProject: "Progress",
      product: "MOVEit Transfer",
      vulnerabilityName: "Progress MOVEit Transfer Deserialization Vulnerability",
      shortDescription: "Progress MOVEit Transfer contains a deserialization of untrusted data vulnerability",
      dateAdded: "2023-06-02",
      dueDate: "2023-06-23",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Known",
    };
    const cats = classifyKevByOwasp(entry as any);
    expect(cats).toContain("A08:2025-Integrity_Failures");
  });
});

// ─── KEV Web Engagement Filter Tests ────────────────────────────────────────

describe("KEV Web Engagement Filter", () => {
  it("filterKevForWebEngagement should include web-relevant entries", async () => {
    const { filterKevForWebEngagement } = await import("./lib/kev-service");
    const catalog = {
      title: "test",
      catalogVersion: "1",
      dateReleased: "2024-01-01",
      count: 3,
      vulnerabilities: [
        {
          cveID: "CVE-2021-44228",
          vendorProject: "Apache",
          product: "Log4j",
          vulnerabilityName: "Log4j RCE",
          shortDescription: "Remote code execution via JNDI injection",
          dateAdded: "2021-12-10",
          dueDate: "2021-12-24",
          requiredAction: "Apply updates",
          knownRansomwareCampaignUse: "Known",
        },
        {
          cveID: "CVE-2024-0002",
          vendorProject: "SomeHardwareVendor",
          product: "Router Firmware",
          vulnerabilityName: "Router Buffer Overflow",
          shortDescription: "A buffer overflow in router firmware allows local privilege escalation",
          dateAdded: "2024-01-01",
          dueDate: "2024-01-15",
          requiredAction: "Apply updates",
          knownRansomwareCampaignUse: "Unknown",
        },
        {
          cveID: "CVE-2023-22515",
          vendorProject: "Atlassian",
          product: "Confluence",
          vulnerabilityName: "Atlassian Confluence Authentication Bypass",
          shortDescription: "Atlassian Confluence allows authentication bypass",
          dateAdded: "2023-10-05",
          dueDate: "2023-10-26",
          requiredAction: "Apply updates",
          knownRansomwareCampaignUse: "Unknown",
        },
      ],
    };
    const filtered = filterKevForWebEngagement(catalog as any);
    // Apache and Atlassian should be included, SomeHardwareVendor should not
    expect(filtered.length).toBe(2);
    expect(filtered.map(v => v.cveID)).toContain("CVE-2021-44228");
    expect(filtered.map(v => v.cveID)).toContain("CVE-2023-22515");
    expect(filtered.map(v => v.cveID)).not.toContain("CVE-2024-0002");
  });
});

// ─── KEV MITRE Technique Mapping Tests ──────────────────────────────────────

describe("KEV Cloud MITRE Technique Mapping", () => {
  it("should map Kubernetes KEV to container techniques", async () => {
    const { mapKevToTechniques } = await import("./lib/kev-service");
    const kev = {
      cveID: "CVE-2024-0001",
      vendorProject: "Kubernetes",
      product: "Kubernetes",
      vulnerabilityName: "Kubernetes RCE",
      shortDescription: "Remote code execution in Kubernetes API server",
      dateAdded: "2024-01-01",
      dueDate: "2024-01-15",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const techniques = mapKevToTechniques(kev as any);
    expect(techniques).toContain("T1610"); // Deploy Container
    expect(techniques).toContain("T1609"); // Container Administration Command
  });

  it("should map Docker KEV to container escape techniques", async () => {
    const { mapKevToTechniques } = await import("./lib/kev-service");
    const kev = {
      cveID: "CVE-2024-0002",
      vendorProject: "Docker",
      product: "Docker",
      vulnerabilityName: "Docker Escape",
      shortDescription: "Container escape vulnerability in Docker runtime",
      dateAdded: "2024-01-01",
      dueDate: "2024-01-15",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const techniques = mapKevToTechniques(kev as any);
    expect(techniques).toContain("T1611"); // Escape to Host
  });

  it("should map CI/CD KEV to supply chain techniques", async () => {
    const { mapKevToTechniques } = await import("./lib/kev-service");
    const kev = {
      cveID: "CVE-2024-0003",
      vendorProject: "JetBrains",
      product: "TeamCity",
      vulnerabilityName: "TeamCity Auth Bypass",
      shortDescription: "Authentication bypass in TeamCity CI server",
      dateAdded: "2024-01-01",
      dueDate: "2024-01-15",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const techniques = mapKevToTechniques(kev as any);
    expect(techniques).toContain("T1195.002"); // Supply Chain Compromise
  });

  it("should map identity provider KEV to auth modification techniques", async () => {
    const { mapKevToTechniques } = await import("./lib/kev-service");
    const kev = {
      cveID: "CVE-2024-0004",
      vendorProject: "Okta",
      product: "Okta",
      vulnerabilityName: "Okta Auth Bypass",
      shortDescription: "Authentication bypass in Okta identity platform",
      dateAdded: "2024-01-01",
      dueDate: "2024-01-15",
      requiredAction: "Apply updates",
      knownRansomwareCampaignUse: "Unknown",
    };
    const techniques = mapKevToTechniques(kev as any);
    expect(techniques).toContain("T1556"); // Modify Authentication Process
  });
});

// ─── Cloud_Enum Enforcement Tests ───────────────────────────────────────────

describe("Cloud_Enum Enforcement in Nmap Knowledge", () => {
  it("getNmapScanPlanContext should mandate cloud_enum for AWS targets", async () => {
    const { getNmapScanPlanContext } = await import("./lib/nmap-knowledge");
    const ctx = getNmapScanPlanContext({
      detectedTech: ["nginx", "php"],
      cloudProvider: "aws",
      hasFirewall: false,
      hasIDS: false,
      stealthRequired: false,
    });
    expect(ctx.toLowerCase()).toContain("cloud_enum");
    expect(ctx.toLowerCase()).toContain("s3scanner");
  });

  it("getNmapScanPlanContext should mandate cloud_enum for Azure targets", async () => {
    const { getNmapScanPlanContext } = await import("./lib/nmap-knowledge");
    const ctx = getNmapScanPlanContext({
      detectedTech: ["iis", "asp.net"],
      cloudProvider: "azure",
      hasFirewall: false,
      hasIDS: false,
      stealthRequired: false,
    });
    expect(ctx.toLowerCase()).toContain("cloud_enum");
  });

  it("getNmapScanPlanContext should not mandate cloud_enum for on-prem targets", async () => {
    const { getNmapScanPlanContext } = await import("./lib/nmap-knowledge");
    const ctx = getNmapScanPlanContext({
      detectedTech: ["apache", "php"],
      cloudProvider: undefined,
      hasFirewall: false,
      hasIDS: false,
      stealthRequired: false,
    });
    // cloud_enum should not be mandated for non-cloud targets
    expect(ctx.toLowerCase()).not.toMatch(/must.*cloud_enum/);
  });
});

// ─── Engagement Orchestrator Wiring Tests ───────────────────────────────────

describe("OWASP and KEV Wiring in Engagement Orchestrator", () => {
  it("engagement-orchestrator should import OWASP knowledge functions", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("getOwaspScanPlanContext");
    expect(content).toContain("getOwaspVulnCorrelationContext");
    expect(content).toContain("getOwaspAssetClassificationContext");
  });

  it("engagement-orchestrator should inject OWASP context into scan plan prompt", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("owaspCtx");
  });

  it("hunt-engine should inject OWASP hunt context", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/hunt-engine.ts", "utf-8");
    expect(content).toContain("getOwaspHuntContext");
    expect(content).toContain("owaspHuntCtx");
  });

  it("scoring-engine should inject OWASP asset classification context", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/scoring-engine.ts", "utf-8");
    expect(content).toContain("getOwaspAssetClassificationContext");
  });
});
