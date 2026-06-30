import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

const ROOT = join(__dirname, "..");

describe("AWS Infrastructure Configuration", () => {
  // ─── CloudFormation Template ──────────────────────────────────────────────
  describe("CloudFormation template (ac3-dev-ecs.yaml)", () => {
    const cfnPath = join(ROOT, "infrastructure/cloudformation/ac3-dev-ecs.yaml");

    it("exists", () => {
      expect(existsSync(cfnPath)).toBe(true);
    });

    it("references the correct ECR URI", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard");
    });

    it("references the pre-existing execution role", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("ac3-dev-ecs-execution-role");
    });

    it("references the pre-existing task role", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("ac3-dev-app-task-role");
    });

    it("includes KMS key parameter", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("KmsKeyArn");
    });

    it("defines required parameters (VpcId, PrivateSubnetIds, PublicSubnetIds)", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("VpcId");
      expect(content).toContain("PrivateSubnetIds");
      expect(content).toContain("PublicSubnetIds");
    });

    it("defines ECS service and task definition resources", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("AWS::ECS::Service");
      expect(content).toContain("AWS::ECS::TaskDefinition");
    });

    it("defines ALB and target group resources", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("AWS::ElasticLoadBalancingV2::LoadBalancer");
      expect(content).toContain("AWS::ElasticLoadBalancingV2::TargetGroup");
    });

    it("includes health check configuration", () => {
      const content = readFileSync(cfnPath, "utf-8");
      expect(content).toContain("/api/health");
    });
  });

  // ─── Terraform dev.tfvars ─────────────────────────────────────────────────
  describe("Terraform dev.tfvars", () => {
    const tfvarsPath = join(ROOT, "infrastructure/terraform/environments/dev.tfvars");

    it("exists", () => {
      expect(existsSync(tfvarsPath)).toBe(true);
    });

    it("sets cross-account ECR account ID", () => {
      const content = readFileSync(tfvarsPath, "utf-8");
      expect(content).toContain('ecr_account_id      = "890319879326"');
    });

    it("sets cross-account ECR repository name", () => {
      const content = readFileSync(tfvarsPath, "utf-8");
      expect(content).toContain('ecr_repository_name = "ace-c3/caldera-dashboard"');
    });

    it("sets the ECR KMS key ARN", () => {
      const content = readFileSync(tfvarsPath, "utf-8");
      expect(content).toContain("arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8");
    });

    it("sets the pre-existing execution role ARN", () => {
      const content = readFileSync(tfvarsPath, "utf-8");
      expect(content).toContain("arn:aws:iam::808038814732:role/ac3-dev-ecs-execution-role");
    });

    it("sets the pre-existing task role ARN", () => {
      const content = readFileSync(tfvarsPath, "utf-8");
      expect(content).toContain("arn:aws:iam::808038814732:role/ac3-dev-app-task-role");
    });
  });

  // ─── Terraform ECS Module ─────────────────────────────────────────────────
  describe("Terraform ECS module supports external roles", () => {
    const ecsMainPath = join(ROOT, "infrastructure/terraform/modules/ecs/main.tf");
    const ecsVarsPath = join(ROOT, "infrastructure/terraform/modules/ecs/variables.tf");

    it("ECS module main.tf exists", () => {
      expect(existsSync(ecsMainPath)).toBe(true);
    });

    it("defines locals for role resolution", () => {
      const content = readFileSync(ecsMainPath, "utf-8");
      expect(content).toContain("use_external_roles");
      expect(content).toContain("execution_role_arn");
      expect(content).toContain("task_role_arn");
      expect(content).toContain("create_roles");
    });

    it("uses local.execution_role_arn in task definition", () => {
      const content = readFileSync(ecsMainPath, "utf-8");
      expect(content).toContain("execution_role_arn       = local.execution_role_arn");
    });

    it("uses local.task_role_arn in task definition", () => {
      const content = readFileSync(ecsMainPath, "utf-8");
      expect(content).toContain("task_role_arn            = local.task_role_arn");
    });

    it("conditionally creates roles with count", () => {
      const content = readFileSync(ecsMainPath, "utf-8");
      expect(content).toContain("count = local.create_roles");
    });

    it("declares external_execution_role_arn variable", () => {
      const content = readFileSync(ecsVarsPath, "utf-8");
      expect(content).toContain("external_execution_role_arn");
    });

    it("declares external_task_role_arn variable", () => {
      const content = readFileSync(ecsVarsPath, "utf-8");
      expect(content).toContain("external_task_role_arn");
    });
  });

  // ─── Terraform Root main.tf ───────────────────────────────────────────────
  describe("Terraform root main.tf cross-account ECR resolution", () => {
    const mainTfPath = join(ROOT, "infrastructure/terraform/main.tf");

    it("defines cross-account ECR local", () => {
      const content = readFileSync(mainTfPath, "utf-8");
      expect(content).toContain("use_cross_account_ecr");
      expect(content).toContain("local.ecr_repository_url");
    });

    it("passes external role ARNs to ECS module", () => {
      const content = readFileSync(mainTfPath, "utf-8");
      expect(content).toContain("external_execution_role_arn = var.external_execution_role_arn");
      expect(content).toContain("external_task_role_arn      = var.external_task_role_arn");
    });
  });

  // ─── Deploy Scripts ───────────────────────────────────────────────────────
  describe("Deployment scripts", () => {
    it("deploy-dev.sh exists and references correct ECR account", () => {
      const path = join(ROOT, "infrastructure/scripts/deploy-dev.sh");
      expect(existsSync(path)).toBe(true);
      const content = readFileSync(path, "utf-8");
      expect(content).toContain('ECR_ACCOUNT_ID="890319879326"');
      expect(content).toContain('ECR_REPO="ace-c3/caldera-dashboard"');
      expect(content).toContain("#!/usr/bin/env bash");
    });

    it("cfn-deploy-dev.sh exists", () => {
      const path = join(ROOT, "infrastructure/scripts/cfn-deploy-dev.sh");
      expect(existsSync(path)).toBe(true);
      const content = readFileSync(path, "utf-8");
      expect(content).toContain("cloudformation deploy");
    });

    it("ecs-exec.sh exists", () => {
      expect(existsSync(join(ROOT, "infrastructure/scripts/ecs-exec.sh"))).toBe(true);
    });

    it("ecs-logs.sh exists", () => {
      expect(existsSync(join(ROOT, "infrastructure/scripts/ecs-logs.sh"))).toBe(true);
    });
  });

  // ─── GitHub Actions Workflow ──────────────────────────────────────────────
  describe("deploy-aws.yml workflow", () => {
    const workflowPath = join(ROOT, ".github/workflows/deploy-aws.yml");

    it("exists", () => {
      expect(existsSync(workflowPath)).toBe(true);
    });

    it("references the cross-account ECR account ID", () => {
      const content = readFileSync(workflowPath, "utf-8");
      expect(content).toContain("890319879326");
    });

    it("references the correct ECR repository name", () => {
      const content = readFileSync(workflowPath, "utf-8");
      expect(content).toContain("ace-c3/caldera-dashboard");
    });
  });

  // ─── Buildspec ────────────────────────────────────────────────────────────
  describe("buildspec.yml", () => {
    const buildspecPath = join(ROOT, "buildspec.yml");

    it("exists", () => {
      expect(existsSync(buildspecPath)).toBe(true);
    });

    it("references the correct ECR account", () => {
      const content = readFileSync(buildspecPath, "utf-8");
      expect(content).toContain("890319879326");
    });
  });
});
