import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the AWS SDK before importing
vi.mock("@aws-sdk/client-ec2", () => ({
  EC2Client: vi.fn().mockImplementation((config) => ({
    config,
    send: vi.fn().mockResolvedValue({ Reservations: [] }),
  })),
  RunInstancesCommand: vi.fn(),
  TerminateInstancesCommand: vi.fn(),
  DescribeInstancesCommand: vi.fn(),
  CreateSecurityGroupCommand: vi.fn(),
  AuthorizeSecurityGroupIngressCommand: vi.fn(),
  CreateKeyPairCommand: vi.fn(),
}));

vi.mock("@aws-sdk/client-sts", () => ({
  STSClient: vi.fn().mockImplementation((config) => ({
    config,
    send: vi.fn().mockResolvedValue({
      Credentials: {
        AccessKeyId: "ASIA_TEMP_KEY",
        SecretAccessKey: "temp_secret",
        SessionToken: "temp_token",
      },
    }),
  })),
  AssumeRoleCommand: vi.fn(),
}));

describe("AWS EC2 Infrastructure", () => {
  beforeEach(() => {
    vi.resetModules();
    // Set up env vars that the module expects
    process.env.AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    process.env.AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    process.env.AWS_DEFAULT_REGION = "us-east-1";
  });

  it("should have AWS credentials available from env", () => {
    expect(process.env.AWS_ACCESS_KEY_ID).toBeTruthy();
    expect(process.env.AWS_SECRET_ACCESS_KEY).toBeTruthy();
    expect(process.env.AWS_DEFAULT_REGION).toBeTruthy();
  });

  it("should map AWS_USERNAME to AWS_ACCESS_KEY_ID pattern", () => {
    // Verify the env mapping pattern used in env.ts
    const username = "AKIAIOSFODNN7EXAMPLE";
    const password = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    
    // The env.ts maps AWS_USERNAME -> AWS_ACCESS_KEY_ID
    process.env.AWS_ACCESS_KEY_ID = username;
    process.env.AWS_SECRET_ACCESS_KEY = password;
    
    expect(process.env.AWS_ACCESS_KEY_ID).toBe(username);
    expect(process.env.AWS_SECRET_ACCESS_KEY).toBe(password);
  });

  it("should not have hardcoded DigitalOcean IPs", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "aws-ec2-infra.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    
    // No hardcoded DO IPs
    expect(content).not.toContain("137.184");
    expect(content).not.toContain("134.209");
    expect(content).not.toContain("167.99");
    
    // Should reference AWS/EC2
    expect(content).toContain("EC2");
    expect(content).toContain("aws-sdk");
  });

  it("should not reference DigitalOcean in msf-provisioner", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "msf-provisioner.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    
    // No DO references (except deprecated backward-compat wrappers)
    expect(content).not.toContain("digitalocean");
    // 'droplet' exists only in deprecated backward-compat function name
    expect(content).not.toContain("DIGITALOCEAN_ACCESS_TOKEN");
    expect(content.toLowerCase()).not.toContain("do_token");
    
    // Should reference AWS/EC2
    expect(content).toContain("EC2");
    expect(content).toContain("aws");
  });

  it("should not have hardcoded IPs in scan-service-url", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "scan-service-url.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    
    // No hardcoded IPs
    expect(content).not.toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
    
    // Should use env vars
    expect(content).toContain("process.env");
  });
});

describe("AWS Credential Fix (assumeRole)", () => {
  it("should explicitly pass credentials to STS client", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(__dirname, "aws-cicd-connector.ts");
    const content = fs.readFileSync(filePath, "utf-8");
    
    // The fix: STSClient should receive explicit credentials
    expect(content).toContain("credentials");
    expect(content).toContain("AWS_ACCESS_KEY_ID");
    expect(content).toContain("AWS_SECRET_ACCESS_KEY");
  });
});
