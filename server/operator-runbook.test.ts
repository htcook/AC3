import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

const ROOT = resolve(__dirname, "..");

function readFile(relPath: string): string {
  const abs = resolve(ROOT, relPath);
  if (!existsSync(abs)) throw new Error(`File not found: ${abs}`);
  return readFileSync(abs, "utf-8");
}

// ─────────────────────────────────────────────────────────────────────────────
// Staging IAM Roles CloudFormation Template
// ─────────────────────────────────────────────────────────────────────────────
describe("ac3-staging-iam-roles.yaml", () => {
  const cfn = readFile("infrastructure/cloudformation/ac3-staging-iam-roles.yaml");

  it("exists and is non-empty", () => {
    expect(cfn.length).toBeGreaterThan(100);
  });

  it("creates the ECS execution role with correct naming", () => {
    expect(cfn).toContain("ecs-execution-role");
    expect(cfn).toContain("EcsExecutionRole");
    expect(cfn).toContain("${ProjectName}-${Environment}-ecs-execution-role");
  });

  it("creates the application task role with correct naming", () => {
    expect(cfn).toContain("app-task-role");
    expect(cfn).toContain("AppTaskRole");
    expect(cfn).toContain("${ProjectName}-${Environment}-app-task-role");
  });

  it("references the cross-account ECR repo (890319879326)", () => {
    expect(cfn).toContain("890319879326");
    expect(cfn).toContain("ace-c3/caldera-dashboard");
  });

  it("references the ECR KMS key ARN", () => {
    expect(cfn).toContain("8e215533-9e88-4cae-b514-93a892e6e6c8");
  });

  it("grants ECR pull permissions to the execution role", () => {
    expect(cfn).toContain("ecr:BatchGetImage");
    expect(cfn).toContain("ecr:GetDownloadUrlForLayer");
    expect(cfn).toContain("ecr:GetAuthorizationToken");
  });

  it("grants Secrets Manager read to the execution role", () => {
    expect(cfn).toContain("secretsmanager:GetSecretValue");
  });

  it("grants S3 read/write to the task role", () => {
    expect(cfn).toContain("s3:GetObject");
    expect(cfn).toContain("s3:PutObject");
  });

  it("grants CloudWatch metrics to the task role", () => {
    expect(cfn).toContain("cloudwatch:PutMetricData");
  });

  it("grants SES send with domain condition", () => {
    expect(cfn).toContain("ses:SendEmail");
    expect(cfn).toContain("aceofcloud.com");
  });

  it("grants ECS Exec (SSM Messages) for debugging", () => {
    expect(cfn).toContain("ssmmessages:CreateControlChannel");
    expect(cfn).toContain("ssmmessages:OpenDataChannel");
  });

  it("outputs both role ARNs", () => {
    expect(cfn).toContain("ExecutionRoleArn");
    expect(cfn).toContain("TaskRoleArn");
  });

  it("outputs a TfvarsSnippet for easy copy-paste", () => {
    expect(cfn).toContain("TfvarsSnippet");
    expect(cfn).toContain("external_execution_role_arn");
    expect(cfn).toContain("external_task_role_arn");
  });

  it("uses least-privilege trust policy with source conditions", () => {
    expect(cfn).toContain("ecs-tasks.amazonaws.com");
    expect(cfn).toContain("aws:SourceArn");
    expect(cfn).toContain("aws:SourceAccount");
  });

  it("includes FedRAMP control tags", () => {
    expect(cfn).toContain("FedRAMP");
    expect(cfn).toContain("AC-6");
  });

  it("supports staging and prod environments", () => {
    expect(cfn).toContain("AllowedValues: [staging, prod]");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Pre-Flight Check Script
// ─────────────────────────────────────────────────────────────────────────────
describe("preflight-check.sh", () => {
  const script = readFile("infrastructure/scripts/preflight-check.sh");

  it("exists and is non-empty", () => {
    expect(script.length).toBeGreaterThan(100);
  });

  it("has a proper shebang", () => {
    expect(script).toMatch(/^#!\/usr\/bin\/env bash/);
  });

  it("checks AWS CLI identity", () => {
    expect(script).toContain("sts get-caller-identity");
  });

  it("checks EC2 permissions", () => {
    expect(script).toContain("ec2 describe-vpcs");
    expect(script).toContain("ec2 describe-subnets");
  });

  it("checks Secrets Manager permissions", () => {
    expect(script).toContain("secretsmanager list-secrets");
    expect(script).toContain("secretsmanager create-secret");
  });

  it("checks CloudFormation permissions", () => {
    expect(script).toContain("cloudformation list-stacks");
    expect(script).toContain("cloudformation validate-template");
  });

  it("checks ECS permissions", () => {
    expect(script).toContain("ecs list-clusters");
  });

  it("checks cross-account ECR permissions", () => {
    expect(script).toContain("890319879326");
    expect(script).toContain("ecr get-authorization-token");
    expect(script).toContain("ecr describe-repositories");
  });

  it("checks IAM permissions for staging role creation", () => {
    expect(script).toContain("iam list-roles");
  });

  it("checks CloudWatch Logs permissions", () => {
    expect(script).toContain("logs describe-log-groups");
  });

  it("checks ELB permissions", () => {
    expect(script).toContain("elbv2 describe-load-balancers");
  });

  it("supports --env and --verbose flags", () => {
    expect(script).toContain("--env");
    expect(script).toContain("--verbose");
  });

  it("prints a clear pass/fail summary", () => {
    expect(script).toContain("Pre-flight check PASSED");
    expect(script).toContain("Pre-flight check FAILED");
  });

  it("cleans up the disposable preflight secret", () => {
    expect(script).toContain("preflight-check");
    expect(script).toContain("force-delete-without-recovery");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Operator Runbook
// ─────────────────────────────────────────────────────────────────────────────
describe("OPERATOR-RUNBOOK.md", () => {
  const runbook = readFile("infrastructure/OPERATOR-RUNBOOK.md");

  it("exists and is substantial", () => {
    expect(runbook.length).toBeGreaterThan(3000);
  });

  it("covers all three steps", () => {
    expect(runbook).toContain("Step 1: Populate Dev Secrets");
    expect(runbook).toContain("Step 2: Deploy Dev ECS Stack");
    expect(runbook).toContain("Step 3: Create Staging IAM Roles");
  });

  it("includes the pre-flight check as Step 0", () => {
    expect(runbook).toContain("Step 0: Pre-Flight Permission Check");
    expect(runbook).toContain("preflight-check.sh");
  });

  it("references the correct ECR URI", () => {
    expect(runbook).toContain("890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard");
  });

  it("references the correct dev account", () => {
    expect(runbook).toContain("808038814732");
  });

  it("includes Docker build and push commands", () => {
    expect(runbook).toContain("docker build");
    expect(runbook).toContain("docker push");
    expect(runbook).toContain("Dockerfile.aws");
  });

  it("includes seed-secrets.sh commands with all modes", () => {
    expect(runbook).toContain("seed-secrets.sh");
    expect(runbook).toContain("--from-env-file");
    expect(runbook).toContain("--dry-run");
    expect(runbook).toContain("--verify");
    expect(runbook).toContain("--interactive");
  });

  it("includes cfn-deploy-dev.sh with auto-discover", () => {
    expect(runbook).toContain("cfn-deploy-dev.sh");
    expect(runbook).toContain("--auto-discover");
  });

  it("includes staging IAM roles deployment command", () => {
    expect(runbook).toContain("ac3-staging-iam-roles.yaml");
    expect(runbook).toContain("CAPABILITY_NAMED_IAM");
  });

  it("includes the TfvarsSnippet retrieval command", () => {
    expect(runbook).toContain("TfvarsSnippet");
    expect(runbook).toContain("external_execution_role_arn");
  });

  it("includes rollback procedures", () => {
    expect(runbook).toContain("Rollback Procedures");
    expect(runbook).toContain("delete-stack");
    expect(runbook).toContain("delete-secret");
  });

  it("includes troubleshooting section", () => {
    expect(runbook).toContain("Troubleshooting");
    expect(runbook).toContain("Essential container exited");
    expect(runbook).toContain("Cross-account ECR pull failed");
  });

  it("includes post-deployment checklist", () => {
    expect(runbook).toContain("Post-Deployment Checklist");
    expect(runbook).toContain("/api/health");
  });

  it("includes file reference table", () => {
    expect(runbook).toContain("File Reference");
    expect(runbook).toContain("preflight-check.sh");
    expect(runbook).toContain("seed-secrets.sh");
    expect(runbook).toContain("ac3-staging-iam-roles.yaml");
  });

  it("credits Harrison Cook / AceofCloud", () => {
    expect(runbook).toContain("Harrison Cook");
    expect(runbook).toContain("AceofCloud");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// File Existence Checks
// ─────────────────────────────────────────────────────────────────────────────
describe("All deployment artifacts exist", () => {
  const requiredFiles = [
    "infrastructure/cloudformation/ac3-dev-ecs.yaml",
    "infrastructure/cloudformation/ac3-staging-iam-roles.yaml",
    "infrastructure/scripts/preflight-check.sh",
    "infrastructure/scripts/seed-secrets.sh",
    "infrastructure/scripts/cfn-deploy-dev.sh",
    "infrastructure/scripts/cfn-deploy-staging.sh",
    "infrastructure/scripts/deploy-dev.sh",
    "infrastructure/scripts/ecs-exec.sh",
    "infrastructure/scripts/ecs-logs.sh",
    "infrastructure/scripts/.env.template",
    "infrastructure/OPERATOR-RUNBOOK.md",
    "infrastructure/DEPLOYMENT.md",
    "infrastructure/terraform/environments/dev.tfvars",
    "infrastructure/terraform/environments/staging.tfvars",
    "infrastructure/terraform/environments/prod.tfvars",
  ];

  for (const file of requiredFiles) {
    it(`${file} exists`, () => {
      expect(existsSync(resolve(ROOT, file))).toBe(true);
    });
  }
});
