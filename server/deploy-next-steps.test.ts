import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, statSync } from "fs";
import { resolve } from "path";

const ROOT = resolve(__dirname, "..");

function readFile(relPath: string): string {
  return readFileSync(resolve(ROOT, relPath), "utf-8");
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Secrets Manager Population Script
// ─────────────────────────────────────────────────────────────────────────────
describe("seed-secrets.sh", () => {
  const script = readFile("infrastructure/scripts/seed-secrets.sh");

  it("exists and is executable", () => {
    const stat = statSync(resolve(ROOT, "infrastructure/scripts/seed-secrets.sh"));
    expect(stat.mode & 0o111).toBeGreaterThan(0);
  });

  it("supports --env, --from-env-file, --interactive, --list, --verify modes", () => {
    expect(script).toContain("--env");
    expect(script).toContain("--from-env-file");
    expect(script).toContain("--interactive");
    expect(script).toContain("--list");
    expect(script).toContain("--verify");
  });

  it("supports --dry-run flag", () => {
    expect(script).toContain("--dry-run");
    expect(script).toContain("DRY_RUN");
  });

  it("supports --kms-key for encryption", () => {
    expect(script).toContain("--kms-key");
    expect(script).toContain("kms-key-id");
  });

  it("uses correct naming convention: ac3/<env>/<SECRET>", () => {
    expect(script).toContain('PREFIX="${PROJECT_NAME}/${ENVIRONMENT}"');
    expect(script).toContain('secret_path="${PREFIX}/${name}"');
  });

  it("includes all secret categories from Terraform secrets module", () => {
    const categories = ["CORE", "FORGE", "AI", "C2", "ASM", "OSINT", "GITHUB", "BOUNTY", "INFRA", "DAST", "STORAGE"];
    for (const cat of categories) {
      expect(script).toContain(`SECRETS_${cat}`);
    }
  });

  it("includes critical core secrets", () => {
    expect(script).toContain("DATABASE_URL");
    expect(script).toContain("JWT_SECRET");
    expect(script).toContain("OAUTH_SERVER_URL");
    expect(script).toContain("CALDERA_API_KEY");
    expect(script).toContain("SHODAN_API_KEY");
  });

  it("includes C2 framework secrets (Cobalt Strike, Empire, Sliver)", () => {
    expect(script).toContain("CS_TEAM_SERVER_URL");
    expect(script).toContain("EMPIRE_BASE_URL");
    expect(script).toContain("SLIVER_SERVER_URL");
  });

  it("includes OSINT expansion secrets", () => {
    expect(script).toContain("BINARYEDGE_API_KEY");
    expect(script).toContain("GREYNOISE_API_KEY");
    expect(script).toContain("VIRUSTOTAL_API_KEY");
    expect(script).toContain("HIBP_API_KEY");
  });

  it("tags secrets with Project, Environment, Category, ManagedBy", () => {
    expect(script).toContain('\\"Key\\":\\"Project\\"');
    expect(script).toContain('\\"Key\\":\\"Environment\\"');
    expect(script).toContain('\\"Key\\":\\"Category\\"');
    expect(script).toContain('\\"Key\\":\\"ManagedBy\\"');
  });

  it("validates environment is dev, staging, or prod", () => {
    expect(script).toContain("^(dev|staging|prod)$");
  });

  it("checks AWS CLI and credentials before proceeding", () => {
    expect(script).toContain("aws sts get-caller-identity");
    expect(script).toContain("command -v aws");
  });

  it("handles .env file parsing with quoted values", () => {
    expect(script).toContain('value="${value#\\"}"');
    expect(script).toContain("IFS= read -r line");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. .env Template
// ─────────────────────────────────────────────────────────────────────────────
describe(".env.template", () => {
  const template = readFile("infrastructure/scripts/.env.template");

  it("exists", () => {
    expect(existsSync(resolve(ROOT, "infrastructure/scripts/.env.template"))).toBe(true);
  });

  it("includes all critical secrets as empty placeholders", () => {
    const required = [
      "DATABASE_URL=",
      "JWT_SECRET=",
      "CALDERA_API_KEY=",
      "CALDERA_BASE_URL=",
      "SHODAN_API_KEY=",
      "OPENAI_API_KEY=",
    ];
    for (const key of required) {
      expect(template).toContain(key);
    }
  });

  it("includes C2 framework secrets", () => {
    expect(template).toContain("CS_TEAM_SERVER_URL=");
    expect(template).toContain("EMPIRE_BASE_URL=");
    expect(template).toContain("SLIVER_SERVER_URL=");
    expect(template).toContain("MSF_RPC_HOST=");
  });

  it("marks Manjusaka as deprecated (commented out)", () => {
    expect(template).toContain("# MANJUSAKA_SERVER_URL=");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Enhanced cfn-deploy-dev.sh
// ─────────────────────────────────────────────────────────────────────────────
describe("cfn-deploy-dev.sh (enhanced)", () => {
  const script = readFile("infrastructure/scripts/cfn-deploy-dev.sh");

  it("exists and is executable", () => {
    const stat = statSync(resolve(ROOT, "infrastructure/scripts/cfn-deploy-dev.sh"));
    expect(stat.mode & 0o111).toBeGreaterThan(0);
  });

  it("supports --auto-discover flag", () => {
    expect(script).toContain("--auto-discover");
    expect(script).toContain("AUTO_DISCOVER=true");
  });

  it("supports --vpc-name for auto-discovery", () => {
    expect(script).toContain("--vpc-name");
    expect(script).toContain('VPC_NAME="ac3-dev"');
  });

  it("discovers VPC by Name tag", () => {
    expect(script).toContain("describe-vpcs");
    expect(script).toContain("tag:Name");
  });

  it("discovers private subnets by tag or MapPublicIpOnLaunch", () => {
    expect(script).toContain("describe-subnets");
    expect(script).toContain("rivate");
    expect(script).toContain("map-public-ip-on-launch");
  });

  it("discovers public subnets by tag or MapPublicIpOnLaunch", () => {
    expect(script).toContain("ublic");
  });

  it("supports --secrets-arn-prefix parameter", () => {
    expect(script).toContain("--secrets-arn-prefix");
    expect(script).toContain("SecretsArnPrefix");
  });

  it("performs post-deploy health check against /api/health", () => {
    expect(script).toContain("/api/health");
    expect(script).toContain("HEALTH_CHECK_TIMEOUT");
    expect(script).toContain("Health check passed");
  });

  it("supports --skip-health-check flag", () => {
    expect(script).toContain("--skip-health-check");
    expect(script).toContain("SKIP_HEALTH_CHECK");
  });

  it("shows troubleshooting steps on health check failure", () => {
    expect(script).toContain("Troubleshooting steps");
    expect(script).toContain("describe-services");
    expect(script).toContain("logs tail");
    expect(script).toContain("describe-target-health");
  });

  it("shows ECS service status after deploy", () => {
    expect(script).toContain("ECS Service Status");
    expect(script).toContain("runningCount");
    expect(script).toContain("desiredCount");
  });

  it("references correct ECR URI", () => {
    expect(script).toContain("890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard");
  });

  it("prints next steps with seed-secrets reference", () => {
    expect(script).toContain("seed-secrets.sh");
    expect(script).toContain("ecs-logs.sh");
    expect(script).toContain("ecs-exec.sh");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Staging CloudFormation deploy script
// ─────────────────────────────────────────────────────────────────────────────
describe("cfn-deploy-staging.sh", () => {
  it("exists and is executable", () => {
    const stat = statSync(resolve(ROOT, "infrastructure/scripts/cfn-deploy-staging.sh"));
    expect(stat.mode & 0o111).toBeGreaterThan(0);
  });

  it("delegates to cfn-deploy-dev.sh with staging defaults", () => {
    const script = readFile("infrastructure/scripts/cfn-deploy-staging.sh");
    expect(script).toContain("cfn-deploy-dev.sh");
    expect(script).toContain("ac3-staging");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Staging tfvars
// ─────────────────────────────────────────────────────────────────────────────
describe("staging.tfvars (updated)", () => {
  const tfvars = readFile("infrastructure/terraform/environments/staging.tfvars");

  it("sets environment to staging", () => {
    expect(tfvars).toContain('environment  = "staging"');
  });

  it("uses 10.20.0.0/16 CIDR (distinct from dev and prod)", () => {
    expect(tfvars).toContain('vpc_cidr              = "10.20.0.0/16"');
  });

  it("includes cross-account ECR configuration", () => {
    expect(tfvars).toContain('ecr_account_id      = "890319879326"');
    expect(tfvars).toContain('ecr_repository_name = "ace-c3/caldera-dashboard"');
    expect(tfvars).toContain("ecr_kms_key_arn");
  });

  it("includes external role ARN placeholders for staging account", () => {
    expect(tfvars).toContain("external_execution_role_arn");
    expect(tfvars).toContain("external_task_role_arn");
  });

  it("has three AZs for HA validation", () => {
    expect(tfvars).toContain("us-east-1a");
    expect(tfvars).toContain("us-east-1b");
    expect(tfvars).toContain("us-east-1c");
  });

  it("enables full FedRAMP security stack", () => {
    expect(tfvars).toContain("enable_guardduty    = true");
    expect(tfvars).toContain("enable_security_hub = true");
    expect(tfvars).toContain("enable_cloudtrail   = true");
    expect(tfvars).toContain("enable_aws_config   = true");
  });

  it("enables WAF", () => {
    expect(tfvars).toContain("enable_waf            = true");
  });

  it("mirrors prod ECS sizing", () => {
    expect(tfvars).toContain("ecs_cpu           = 1024");
    expect(tfvars).toContain("ecs_memory        = 2048");
    expect(tfvars).toContain("ecs_desired_count = 2");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Prod tfvars (updated with ECR)
// ─────────────────────────────────────────────────────────────────────────────
describe("prod.tfvars (updated)", () => {
  const tfvars = readFile("infrastructure/terraform/environments/prod.tfvars");

  it("includes cross-account ECR configuration", () => {
    expect(tfvars).toContain('ecr_account_id      = "890319879326"');
    expect(tfvars).toContain('ecr_repository_name = "ace-c3/caldera-dashboard"');
  });

  it("includes external role ARN placeholders", () => {
    expect(tfvars).toContain("external_execution_role_arn");
    expect(tfvars).toContain("external_task_role_arn");
  });

  it("has deletion protection enabled", () => {
    expect(tfvars).toContain("db_deletion_protection = true");
  });

  it("has 35-day backup retention", () => {
    expect(tfvars).toContain("db_backup_retention_days = 35");
  });

  it("uses 10.30.0.0/16 CIDR", () => {
    expect(tfvars).toContain('vpc_cidr              = "10.30.0.0/16"');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Cross-environment consistency
// ─────────────────────────────────────────────────────────────────────────────
describe("Cross-environment consistency", () => {
  const dev = readFile("infrastructure/terraform/environments/dev.tfvars");
  const staging = readFile("infrastructure/terraform/environments/staging.tfvars");
  const prod = readFile("infrastructure/terraform/environments/prod.tfvars");

  it("all environments reference the same ECR account", () => {
    for (const tfvars of [dev, staging, prod]) {
      expect(tfvars).toContain("890319879326");
    }
  });

  it("all environments reference the same ECR repository", () => {
    for (const tfvars of [dev, staging, prod]) {
      expect(tfvars).toContain("ace-c3/caldera-dashboard");
    }
  });

  it("all environments use us-east-1", () => {
    for (const tfvars of [dev, staging, prod]) {
      expect(tfvars).toContain('aws_region   = "us-east-1"');
    }
  });

  it("VPC CIDRs are distinct across environments", () => {
    expect(dev).toContain("10.10.0.0/16");
    expect(staging).toContain("10.20.0.0/16");
    expect(prod).toContain("10.30.0.0/16");
  });

  it("dev has external role ARNs populated, staging/prod have placeholders", () => {
    // Dev has actual ARNs
    expect(dev).toContain("arn:aws:iam::808038814732:role/ac3-dev-ecs-execution-role");
    // Staging and prod have empty strings (Terraform creates roles)
    expect(staging).toContain('external_execution_role_arn = ""');
    expect(prod).toContain('external_execution_role_arn = ""');
  });

  it("security controls escalate from dev to prod", () => {
    // Dev: minimal
    expect(dev).toContain("enable_guardduty    = false");
    // Staging + Prod: full
    expect(staging).toContain("enable_guardduty    = true");
    expect(prod).toContain("enable_guardduty    = true");
  });
});
