import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const ROOT = path.resolve(__dirname, "..");

// ═══════════════════════════════════════════════
// 1. Calibration Dashboard Widget
// ═══════════════════════════════════════════════
describe("Calibration Dashboard Widget", () => {
  const widgetPath = path.join(ROOT, "client/src/components/CalibrationDashboardWidget.tsx");

  it("component file exists", () => {
    expect(fs.existsSync(widgetPath)).toBe(true);
  });

  it("exports a default or named component", () => {
    const content = fs.readFileSync(widgetPath, "utf-8");
    expect(
      content.includes("export default") || content.includes("export function") || content.includes("export const")
    ).toBe(true);
  });

  it("renders drift status and rejection patterns", () => {
    const content = fs.readFileSync(widgetPath, "utf-8");
    expect(content).toMatch(/drift|calibration/i);
    expect(content).toMatch(/rejection|pattern/i);
  });

  it("is wired into BugBountyWorkspace", () => {
    const workspace = fs.readFileSync(
      path.join(ROOT, "client/src/pages/BugBountyWorkspace.tsx"),
      "utf-8"
    );
    expect(workspace).toMatch(/CalibrationDashboardWidget/);
  });
});

// ═══════════════════════════════════════════════
// 2. Submission History UI Tab
// ═══════════════════════════════════════════════
describe("Submission History UI Tab", () => {
  const tabPath = path.join(ROOT, "client/src/components/SubmissionHistoryTab.tsx");

  it("component file exists", () => {
    expect(fs.existsSync(tabPath)).toBe(true);
  });

  it("renders analytics data (win-rate, platform breakdown)", () => {
    const content = fs.readFileSync(tabPath, "utf-8");
    expect(content).toMatch(/win.*rate|analytics|platform/i);
  });

  it("is wired into SubmissionPrep page as a tab", () => {
    const prep = fs.readFileSync(
      path.join(ROOT, "client/src/pages/SubmissionPrep.tsx"),
      "utf-8"
    );
    expect(prep).toMatch(/SubmissionHistoryTab/);
    expect(prep).toMatch(/history/i);
  });
});

// ═══════════════════════════════════════════════
// 3. API Health Dashboard
// ═══════════════════════════════════════════════
describe("API Health Dashboard", () => {
  const dashPath = path.join(ROOT, "client/src/pages/ApiHealthDashboard.tsx");

  it("page file exists", () => {
    expect(fs.existsSync(dashPath)).toBe(true);
  });

  it("shows integration health status", () => {
    const content = fs.readFileSync(dashPath, "utf-8");
    expect(content).toMatch(/health|status|latency/i);
  });

  it("uses tRPC queries for health data", () => {
    const content = fs.readFileSync(dashPath, "utf-8");
    expect(content).toMatch(/trpc\./);
  });

  it("is registered in App.tsx routes", () => {
    const app = fs.readFileSync(path.join(ROOT, "client/src/App.tsx"), "utf-8");
    expect(app).toMatch(/ApiHealthDashboard/);
    expect(app).toMatch(/\/api-health/);
  });

  it("is in the sidebar navigation", () => {
    const nav = fs.readFileSync(
      path.join(ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(nav).toMatch(/API Health Dashboard/);
    expect(nav).toMatch(/\/api-health/);
  });
});

// ═══════════════════════════════════════════════
// 4. PR Infrastructure Check Workflow
// ═══════════════════════════════════════════════
describe("PR Infrastructure Check Workflow", () => {
  const wfPath = path.join(ROOT, ".github/workflows/pr-infra-check.yml");

  it("workflow file exists", () => {
    expect(fs.existsSync(wfPath)).toBe(true);
  });

  it("triggers on pull requests to main", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/pull_request/);
    expect(content).toMatch(/main/);
  });

  it("only triggers on infrastructure file changes", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/infrastructure\/\*\*/);
  });

  it("includes Terraform format check", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/terraform fmt/);
  });

  it("includes Terraform validate", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/terraform validate/);
  });

  it("includes tflint", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/tflint/);
  });

  it("includes CloudFormation validation with cfn-lint", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/cfn-lint/);
  });

  it("includes shellcheck for scripts", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/shellcheck/);
  });
});

// ═══════════════════════════════════════════════
// 5. Security Scanning Workflow
// ═══════════════════════════════════════════════
describe("Security Scanning Workflow", () => {
  const wfPath = path.join(ROOT, ".github/workflows/security-scan.yml");

  it("workflow file exists", () => {
    expect(fs.existsSync(wfPath)).toBe(true);
  });

  it("triggers on push, PR, and weekly schedule", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/push/);
    expect(content).toMatch(/pull_request/);
    expect(content).toMatch(/schedule/);
  });

  it("includes npm audit job", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/npm.*audit|pnpm.*audit/i);
  });

  it("includes Trivy container scan", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/trivy/i);
    expect(content).toMatch(/aquasecurity\/trivy-action/);
  });

  it("includes Trivy filesystem/secret scan", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/scan-type.*fs|scanners.*secret/i);
  });

  it("includes SBOM generation with CycloneDX", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/cyclonedx/i);
    expect(content).toMatch(/sbom/i);
  });

  it("includes license compliance check", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/license/i);
    expect(content).toMatch(/GPL|copyleft/i);
  });

  it("uploads SARIF to GitHub Security tab", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/upload-sarif/);
    expect(content).toMatch(/sarif/i);
  });

  it("uses Dockerfile.aws for container build", () => {
    const content = fs.readFileSync(wfPath, "utf-8");
    expect(content).toMatch(/Dockerfile\.aws/);
  });
});

// ═══════════════════════════════════════════════
// 6. Monitoring/Alerting CloudFormation Template
// ═══════════════════════════════════════════════
describe("Monitoring CloudFormation Template", () => {
  const cfnPath = path.join(ROOT, "infrastructure/cloudformation/ac3-monitoring.yaml");

  it("template file exists", () => {
    expect(fs.existsSync(cfnPath)).toBe(true);
  });

  const content = fs.readFileSync(
    path.join(ROOT, "infrastructure/cloudformation/ac3-monitoring.yaml"),
    "utf-8"
  );

  it("includes SNS topic for alarms", () => {
    expect(content).toMatch(/AWS::SNS::Topic/);
  });

  it("includes ECS CPU alarm", () => {
    expect(content).toMatch(/CPUUtilization/);
    expect(content).toMatch(/AWS::CloudWatch::Alarm/);
  });

  it("includes ECS memory alarm", () => {
    expect(content).toMatch(/MemoryUtilization/);
  });

  it("includes ECS task count alarm", () => {
    expect(content).toMatch(/RunningTaskCount/);
  });

  it("includes ALB 5xx alarm", () => {
    expect(content).toMatch(/HTTPCode_ELB_5XX_Count/);
  });

  it("includes ALB 4xx alarm", () => {
    expect(content).toMatch(/HTTPCode_ELB_4XX_Count/);
  });

  it("includes unhealthy host alarm", () => {
    expect(content).toMatch(/UnHealthyHostCount/);
  });

  it("includes target response time alarm", () => {
    expect(content).toMatch(/TargetResponseTime/);
  });

  it("includes application error rate metric filter", () => {
    expect(content).toMatch(/AWS::Logs::MetricFilter/);
    expect(content).toMatch(/ApplicationErrors/);
  });

  it("includes fatal error alarm", () => {
    expect(content).toMatch(/FatalErrors/);
  });

  it("includes CloudWatch dashboard", () => {
    expect(content).toMatch(/AWS::CloudWatch::Dashboard/);
  });

  it("includes Slack notification Lambda (optional)", () => {
    expect(content).toMatch(/AWS::Lambda::Function/);
    expect(content).toMatch(/slack/i);
  });

  it("has configurable thresholds via parameters", () => {
    expect(content).toMatch(/CPUAlarmThreshold/);
    expect(content).toMatch(/MemoryAlarmThreshold/);
    expect(content).toMatch(/ALB5xxThreshold/);
  });

  it("includes log retention with prod/dev differentiation", () => {
    expect(content).toMatch(/RetentionInDays/);
    expect(content).toMatch(/IsProd/);
  });
});

// ═══════════════════════════════════════════════
// 7. Terraform State Locking Module
// ═══════════════════════════════════════════════
describe("Terraform State Locking Module", () => {
  const modulePath = path.join(ROOT, "infrastructure/terraform/modules/state-locking/main.tf");

  it("module file exists", () => {
    expect(fs.existsSync(modulePath)).toBe(true);
  });

  const content = fs.readFileSync(
    path.join(ROOT, "infrastructure/terraform/modules/state-locking/main.tf"),
    "utf-8"
  );

  it("creates DynamoDB table for state locking", () => {
    expect(content).toMatch(/aws_dynamodb_table/);
    expect(content).toMatch(/LockID/);
  });

  it("uses PAY_PER_REQUEST billing", () => {
    expect(content).toMatch(/PAY_PER_REQUEST/);
  });

  it("enables point-in-time recovery", () => {
    expect(content).toMatch(/point_in_time_recovery/);
  });

  it("creates S3 bucket for state storage", () => {
    expect(content).toMatch(/aws_s3_bucket/);
    expect(content).toMatch(/tf-state/);
  });

  it("enables S3 versioning", () => {
    expect(content).toMatch(/aws_s3_bucket_versioning/);
  });

  it("enables S3 server-side encryption with KMS", () => {
    expect(content).toMatch(/aws_s3_bucket_server_side_encryption/);
    expect(content).toMatch(/aws:kms/);
  });

  it("blocks public access on S3 bucket", () => {
    expect(content).toMatch(/aws_s3_bucket_public_access_block/);
    expect(content).toMatch(/block_public_acls/);
  });

  it("enforces SSL-only access via bucket policy", () => {
    expect(content).toMatch(/EnforceSSLOnly/);
    expect(content).toMatch(/aws:SecureTransport/);
  });

  it("has prevent_destroy lifecycle rules", () => {
    expect(content).toMatch(/prevent_destroy.*=.*true/);
  });

  it("outputs backend configuration snippet", () => {
    expect(content).toMatch(/backend_config/);
    expect(content).toMatch(/dynamodb_table/);
  });

  it("aligns with existing backend config naming", () => {
    // Verify the module produces names matching the existing backend-dev.hcl
    expect(content).toMatch(/tf-locks/);
    expect(content).toMatch(/tf-state/);
  });
});

// ═══════════════════════════════════════════════
// 8. Existing Backend Configs Reference State Locking
// ═══════════════════════════════════════════════
describe("Backend Configs Reference State Locking", () => {
  const envDir = path.join(ROOT, "infrastructure/terraform/environments");

  it("dev backend references DynamoDB table", () => {
    const content = fs.readFileSync(path.join(envDir, "backend-dev.hcl"), "utf-8");
    expect(content).toMatch(/dynamodb_table/);
    expect(content).toMatch(/ac3-terraform-locks/);
  });

  it("staging backend references DynamoDB table", () => {
    const content = fs.readFileSync(path.join(envDir, "backend-staging.hcl"), "utf-8");
    expect(content).toMatch(/dynamodb_table/);
    expect(content).toMatch(/ac3-terraform-locks/);
  });

  it("prod backend references DynamoDB table", () => {
    const content = fs.readFileSync(path.join(envDir, "backend-prod.hcl"), "utf-8");
    expect(content).toMatch(/dynamodb_table/);
    expect(content).toMatch(/ac3-terraform-locks/);
  });

  it("all backends use encryption", () => {
    for (const env of ["dev", "staging", "prod"]) {
      const content = fs.readFileSync(path.join(envDir, `backend-${env}.hcl`), "utf-8");
      expect(content).toMatch(/encrypt.*=.*true/);
    }
  });
});
