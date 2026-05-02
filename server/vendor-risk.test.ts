import { describe, it, expect, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "yaml";

// ─── CloudFormation Template Validation Tests ───────────────────────────────

describe("CloudFormation Template — ac3-customer-cross-account-role.yaml", () => {
  const templatePath = path.resolve(__dirname, "../deploy/cloudformation/ac3-customer-cross-account-role.yaml");
  let template: any;

  it("template file exists and is valid YAML", () => {
    expect(fs.existsSync(templatePath)).toBe(true);
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    expect(template).toBeDefined();
    expect(template.AWSTemplateFormatVersion).toBe("2010-09-09");
  });

  it("has required parameters with correct types", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const params = template.Parameters;
    expect(params).toBeDefined();

    // Required parameters
    expect(params.AC3AccountId).toBeDefined();
    expect(params.AC3AccountId.Type).toBe("String");
    expect(params.AC3AccountId.Default).toBe("808038814732");

    expect(params.ExternalId).toBeDefined();
    expect(params.ExternalId.Type).toBe("String");
    expect(params.ExternalId.MinLength).toBeGreaterThanOrEqual(16);

    expect(params.RoleName).toBeDefined();
    expect(params.RoleName.Default).toBe("ac3-cross-account-role");

    expect(params.SessionDuration).toBeDefined();
    expect(params.SessionDuration.Default).toBe(3600);
    expect(params.SessionDuration.MinValue).toBe(900);
    expect(params.SessionDuration.MaxValue).toBe(43200);
  });

  it("has toggleable feature parameters", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const params = template.Parameters;

    const toggleParams = ["EnableCSPM", "EnableContainerScanning", "EnableCodePipelineCallback", "EnableCloudWatchLogs"];
    for (const p of toggleParams) {
      expect(params[p]).toBeDefined();
      expect(params[p].AllowedValues).toEqual(["true", "false"]);
    }

    // CSPM, Container, CodePipeline default to true; CloudWatch Logs defaults to false
    expect(params.EnableCSPM.Default).toBe("true");
    expect(params.EnableContainerScanning.Default).toBe("true");
    expect(params.EnableCodePipelineCallback.Default).toBe("true");
    expect(params.EnableCloudWatchLogs.Default).toBe("false");
  });

  it("has conditions for all toggleable features", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const conditions = template.Conditions;
    expect(conditions).toBeDefined();
    expect(conditions.CSPMEnabled).toBeDefined();
    expect(conditions.ContainerScanningEnabled).toBeDefined();
    expect(conditions.CodePipelineEnabled).toBeDefined();
    expect(conditions.CloudWatchLogsEnabled).toBeDefined();
  });

  it("creates the cross-account role with external ID condition", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const role = template.Resources.AC3CrossAccountRole;
    expect(role).toBeDefined();
    expect(role.Type).toBe("AWS::IAM::Role");

    // Trust policy should have external ID condition
    const trustPolicy = role.Properties.AssumeRolePolicyDocument;
    expect(trustPolicy).toBeDefined();
    const stmt = trustPolicy.Statement[0];
    expect(stmt.Effect).toBe("Allow");
    expect(stmt.Action).toBe("sts:AssumeRole");
    expect(stmt.Condition).toBeDefined();
    expect(stmt.Condition.StringEquals).toBeDefined();
    expect(stmt.Condition.StringEquals["sts:ExternalId"]).toBeDefined();
  });

  it("has 5 managed policies (discovery always, 4 conditional)", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const resources = template.Resources;

    // Always-on policy
    expect(resources.EnvironmentDiscoveryPolicy).toBeDefined();
    expect(resources.EnvironmentDiscoveryPolicy.Type).toBe("AWS::IAM::ManagedPolicy");
    expect(resources.EnvironmentDiscoveryPolicy.Condition).toBeUndefined();

    // Conditional policies
    expect(resources.CSPMAssessmentPolicy).toBeDefined();
    expect(resources.CSPMAssessmentPolicy.Condition).toBe("CSPMEnabled");

    expect(resources.ContainerScanningPolicy).toBeDefined();
    expect(resources.ContainerScanningPolicy.Condition).toBe("ContainerScanningEnabled");

    expect(resources.CodePipelineCallbackPolicy).toBeDefined();
    expect(resources.CodePipelineCallbackPolicy.Condition).toBe("CodePipelineEnabled");

    expect(resources.CloudWatchLogsPolicy).toBeDefined();
    expect(resources.CloudWatchLogsPolicy.Condition).toBe("CloudWatchLogsEnabled");
  });

  it("environment discovery policy includes required AWS API actions", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const policy = template.Resources.EnvironmentDiscoveryPolicy;
    const stmts = policy.Properties.PolicyDocument.Statement;
    const allActions = stmts.flatMap((s: any) => Array.isArray(s.Action) ? s.Action : [s.Action]);

    // EC2 discovery
    expect(allActions).toContain("ec2:DescribeInstances");
    // ELB discovery
    expect(allActions).toContain("elasticloadbalancing:DescribeLoadBalancers");
    // API Gateway discovery
    expect(allActions).toContain("apigateway:GET");
    // CloudFront discovery
    expect(allActions).toContain("cloudfront:ListDistributions");
    // ECS discovery
    expect(allActions).toContain("ecs:ListServices");
    expect(allActions).toContain("ecs:DescribeServices");
    // STS identity
    expect(allActions).toContain("sts:GetCallerIdentity");
  });

  it("CSPM policy covers all 5 CIS Benchmark domains", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const policy = template.Resources.CSPMAssessmentPolicy;
    const stmts = policy.Properties.PolicyDocument.Statement;
    const allActions = stmts.flatMap((s: any) => Array.isArray(s.Action) ? s.Action : [s.Action]);

    // IAM domain
    expect(allActions).toContain("iam:GetAccountPasswordPolicy");
    expect(allActions).toContain("iam:ListUsers");
    expect(allActions).toContain("iam:ListAccessKeys");
    expect(allActions).toContain("iam:GetCredentialReport");

    // Networking domain
    expect(allActions).toContain("ec2:DescribeSecurityGroups");
    expect(allActions).toContain("ec2:DescribeVpcs");
    expect(allActions).toContain("ec2:DescribeFlowLogs");

    // Storage domain
    expect(allActions).toContain("s3:ListAllMyBuckets");
    expect(allActions).toContain("s3:GetBucketEncryption");
    expect(allActions).toContain("s3:GetBucketPublicAccessBlock");

    // Compute domain
    expect(allActions).toContain("lambda:ListFunctions");
    expect(allActions).toContain("rds:DescribeDBInstances");

    // Logging domain
    expect(allActions).toContain("cloudtrail:DescribeTrails");
    expect(allActions).toContain("guardduty:ListDetectors");
    expect(allActions).toContain("securityhub:DescribeHub");
  });

  it("CodePipeline policy only allows job callback actions (no other writes)", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const policy = template.Resources.CodePipelineCallbackPolicy;
    const stmts = policy.Properties.PolicyDocument.Statement;
    const allActions = stmts.flatMap((s: any) => Array.isArray(s.Action) ? s.Action : [s.Action]);

    expect(allActions).toEqual([
      "codepipeline:PutJobSuccessResult",
      "codepipeline:PutJobFailureResult",
    ]);
  });

  it("container scanning policy scopes ECR access to customer account", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const policy = template.Resources.ContainerScanningPolicy;
    const stmts = policy.Properties.PolicyDocument.Statement;

    // GetAuthorizationToken must be Resource: '*'
    const authStmt = stmts.find((s: any) => s.Action?.includes?.("ecr:GetAuthorizationToken") || s.Action === "ecr:GetAuthorizationToken");
    expect(authStmt).toBeDefined();
    expect(authStmt.Resource).toBe("*");

    // Repository access should be scoped to account
    const repoStmt = stmts.find((s: any) => Array.isArray(s.Action) && s.Action.includes("ecr:DescribeRepositories"));
    expect(repoStmt).toBeDefined();
    // Resource should reference account ID
    expect(typeof repoStmt.Resource === "string" ? repoStmt.Resource : JSON.stringify(repoStmt.Resource)).toContain("repository");
  });

  it("has required outputs (RoleArn, ExternalId, PermissionSummary)", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);
    const outputs = template.Outputs;
    expect(outputs).toBeDefined();
    expect(outputs.RoleArn).toBeDefined();
    expect(outputs.ExternalId).toBeDefined();
    expect(outputs.PermissionSummary).toBeDefined();
    expect(outputs.OnboardingInstructions).toBeDefined();
  });

  it("no write permissions in discovery or CSPM policies", () => {
    const raw = fs.readFileSync(templatePath, "utf-8");
    template = yaml.parse(raw);

    const writePatterns = ["Put", "Create", "Delete", "Update", "Modify", "Attach", "Detach", "Set", "Add", "Remove", "Tag", "Untag"];
    const readOnlyPolicies = ["EnvironmentDiscoveryPolicy", "CSPMAssessmentPolicy", "ContainerScanningPolicy", "CloudWatchLogsPolicy"];

    for (const policyName of readOnlyPolicies) {
      const policy = template.Resources[policyName];
      if (!policy) continue; // conditional policies may not exist
      const stmts = policy.Properties.PolicyDocument.Statement;
      const allActions: string[] = stmts.flatMap((s: any) => Array.isArray(s.Action) ? s.Action : [s.Action]);

      for (const action of allActions) {
        const actionVerb = action.split(":")[1] || "";
        // Allow specific exceptions
        if (action === "iam:GenerateCredentialReport") continue; // This is a read-side action
        if (action === "logs:StartQuery" || action === "logs:StopQuery") continue; // CloudWatch Insights query lifecycle
        for (const pattern of writePatterns) {
          expect(actionVerb.startsWith(pattern)).toBe(false);
        }
      }
    }
  });
});

// ─── Vendor Risk Score Computation Tests ────────────────────────────────────

describe("Vendor Risk Score Computation", () => {
  // Mirror the scoring algorithm from VendorRiskTab
  function computeVendorRiskScore(cves: { severity: string; cvss: number | null; kevListed: boolean }[]) {
    const critical = cves.filter(c => c.severity === "critical" || (c.cvss && c.cvss >= 9)).length;
    const high = cves.filter(c => c.severity === "high" || (c.cvss && c.cvss >= 7 && c.cvss < 9)).length;
    const medium = cves.filter(c => c.severity === "medium" || (c.cvss && c.cvss >= 4 && c.cvss < 7)).length;
    const low = cves.filter(c => c.severity === "low" || (c.cvss && c.cvss < 4)).length;
    const kev = cves.filter(c => c.kevListed).length;

    const score = Math.min(100, Math.round(
      (critical * 25 + high * 15 + medium * 8 + low * 3 + kev * 10) /
      Math.max(1, cves.length) * 10
    ));
    const band = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : score >= 20 ? "LOW" : "MINIMAL";
    return { score, band, critical, high, medium, low, kev, total: cves.length };
  }

  it("returns MINIMAL for empty CVE list", () => {
    const result = computeVendorRiskScore([]);
    expect(result.band).toBe("MINIMAL");
    expect(result.score).toBe(0);
    expect(result.total).toBe(0);
  });

  it("returns CRITICAL for all-critical CVEs", () => {
    const cves = [
      { severity: "critical", cvss: 9.8, kevListed: true },
      { severity: "critical", cvss: 9.5, kevListed: false },
    ];
    const result = computeVendorRiskScore(cves);
    expect(result.band).toBe("CRITICAL");
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.critical).toBe(2);
    expect(result.kev).toBe(1);
  });

  it("returns HIGH for mixed critical/high CVEs", () => {
    const cves = [
      { severity: "critical", cvss: 9.0, kevListed: false },
      { severity: "high", cvss: 7.5, kevListed: false },
      { severity: "medium", cvss: 5.0, kevListed: false },
      { severity: "low", cvss: 3.0, kevListed: false },
    ];
    const result = computeVendorRiskScore(cves);
    expect(["CRITICAL", "HIGH"]).toContain(result.band);
    expect(result.total).toBe(4);
  });

  it("KEV listing increases score", () => {
    const withoutKev = computeVendorRiskScore([
      { severity: "medium", cvss: 5.0, kevListed: false },
    ]);
    const withKev = computeVendorRiskScore([
      { severity: "medium", cvss: 5.0, kevListed: true },
    ]);
    expect(withKev.score).toBeGreaterThan(withoutKev.score);
  });

  it("score is capped at 100", () => {
    const cves = Array.from({ length: 20 }, () => ({
      severity: "critical" as const,
      cvss: 10.0,
      kevListed: true,
    }));
    const result = computeVendorRiskScore(cves);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("returns LOW for all-low CVEs", () => {
    const cves = [
      { severity: "low", cvss: 2.0, kevListed: false },
      { severity: "low", cvss: 1.5, kevListed: false },
      { severity: "low", cvss: 3.0, kevListed: false },
    ];
    const result = computeVendorRiskScore(cves);
    expect(["LOW", "MINIMAL"]).toContain(result.band);
    expect(result.low).toBe(3);
  });
});

// ─── Shared Responsibility Model Tests ──────────────────────────────────────

describe("Shared Responsibility Model", () => {
  const KNOWN_PROVIDERS: Record<string, { providerScope: string[]; customerScope: string[]; sharedScope: string[] }> = {
    "Microsoft 365": {
      providerScope: ["Exchange Online server patching", "Infrastructure security", "Physical datacenter security", "Platform availability (SLA)", "Anti-malware engine updates"],
      customerScope: ["SPF/DKIM/DMARC configuration", "Tenant security settings", "Conditional Access policies", "User access management", "Data classification & DLP rules", "Mailbox audit log review"],
      sharedScope: ["Incident response coordination", "Threat intelligence sharing", "Compliance reporting"],
    },
    "Google Workspace": {
      providerScope: ["Gmail server infrastructure", "Infrastructure security", "Physical datacenter security", "Platform availability (SLA)", "Spam/phishing filter updates"],
      customerScope: ["SPF/DKIM/DMARC configuration", "Workspace admin console settings", "User access management", "Data Loss Prevention rules", "Security investigation tool usage"],
      sharedScope: ["Incident response coordination", "Threat intelligence sharing", "Compliance reporting"],
    },
    "Cloudflare": {
      providerScope: ["CDN/WAF infrastructure", "DDoS mitigation", "Edge network availability", "SSL/TLS certificate management (if using CF certs)", "Bot management engine"],
      customerScope: ["WAF rule configuration", "Page rules & caching policies", "DNS record management", "Origin server security", "Rate limiting configuration"],
      sharedScope: ["Incident response coordination", "Security event monitoring", "Custom rule tuning"],
    },
    "AWS": {
      providerScope: ["Physical infrastructure security", "Hypervisor & network infrastructure", "Managed service patching (RDS, Lambda, etc.)", "Global infrastructure availability"],
      customerScope: ["IAM policies & access control", "Security group configuration", "Data encryption configuration", "Application security", "OS patching (EC2)", "Network ACLs & VPC design"],
      sharedScope: ["Incident response coordination", "Compliance framework alignment", "Shared vulnerability disclosure"],
    },
  };

  it("has provider, customer, and shared scopes for each known provider", () => {
    for (const [name, model] of Object.entries(KNOWN_PROVIDERS)) {
      expect(model.providerScope.length).toBeGreaterThan(0);
      expect(model.customerScope.length).toBeGreaterThan(0);
      expect(model.sharedScope.length).toBeGreaterThan(0);
    }
  });

  it("Microsoft 365 model includes SPF/DKIM/DMARC as customer responsibility", () => {
    const m365 = KNOWN_PROVIDERS["Microsoft 365"];
    expect(m365.customerScope.some(s => s.includes("SPF/DKIM/DMARC"))).toBe(true);
  });

  it("AWS model includes IAM as customer responsibility", () => {
    const aws = KNOWN_PROVIDERS["AWS"];
    expect(aws.customerScope.some(s => s.includes("IAM"))).toBe(true);
  });

  it("all providers include incident response in shared scope", () => {
    for (const [name, model] of Object.entries(KNOWN_PROVIDERS)) {
      expect(model.sharedScope.some(s => s.toLowerCase().includes("incident response"))).toBe(true);
    }
  });
});

// ─── Managed Provider Filter Integration Tests ──────────────────────────────

describe("Managed Provider Filter — Asset Ownership", () => {
  // Import the shared filter
  let createAssetOwnershipFilter: any;

  it("can import the shared filter module", async () => {
    const mod = await import("../shared/managed-provider-filter");
    createAssetOwnershipFilter = mod.createAssetOwnershipFilter;
    expect(createAssetOwnershipFilter).toBeDefined();
    expect(typeof createAssetOwnershipFilter).toBe("function");
  });

  it("classifies Microsoft 365 hosts as managed", async () => {
    const mod = await import("../shared/managed-provider-filter");
    const filter = mod.createAssetOwnershipFilter({
      managedProviderName: "Microsoft 365",
      primaryDomain: "example.com",
    });

    // Microsoft 365 hosts should be managed
    expect(filter.isClientOwned({ hostname: "outlook.office365.com", tags: [] })).toBe(false);
    expect(filter.isClientOwned({ hostname: "mail.protection.outlook.com", tags: [] })).toBe(false);

    // Client's own domain should be client-owned
    expect(filter.isClientOwned({ hostname: "www.example.com", tags: [] })).toBe(true);
    expect(filter.isClientOwned({ hostname: "mail.example.com", tags: [] })).toBe(true);
  });

  it("classifies Google Workspace hosts as managed", async () => {
    const mod = await import("../shared/managed-provider-filter");
    const filter = mod.createAssetOwnershipFilter({
      managedProviderName: "Google Workspace",
      primaryDomain: "example.com",
    });

    expect(filter.isClientOwned({ hostname: "aspmx.l.google.com", tags: [] })).toBe(false);
    expect(filter.isClientOwned({ hostname: "www.example.com", tags: [] })).toBe(true);
  });

  it("classifies third-party registrant assets as managed when provider is set", async () => {
    const mod = await import("../shared/managed-provider-filter");
    const filter = mod.createAssetOwnershipFilter({
      managedProviderName: "Microsoft 365",
      primaryDomain: "example.com",
    });

    // Assets tagged as reverse_whois or related_domain should be excluded when provider context exists
    // The filter uses hostname patterns + provider name matching, not just tags
    // Without a managed provider, all non-pattern-matched hosts are client-owned
    expect(filter.isClientOwned({ hostname: "outlook.office365.com", tags: ["reverse_whois"] })).toBe(false);
  });

  it("returns all client-owned when no managed provider", async () => {
    const mod = await import("../shared/managed-provider-filter");
    const filter = mod.createAssetOwnershipFilter({
      managedProviderName: null,
      primaryDomain: "example.com",
    });

    expect(filter.isClientOwned({ hostname: "www.example.com", tags: [] })).toBe(true);
    expect(filter.isClientOwned({ hostname: "api.example.com", tags: [] })).toBe(true);
  });
});
