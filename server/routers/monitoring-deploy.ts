/**
 * Monitoring Deployment Router
 * 
 * Provides server-side procedures for:
 * - Generating deployment commands with user-specified parameters
 * - Tracking deployment state (pre-deploy checklist, deployment history)
 * - Validating configuration before deployment
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface DeploymentConfig {
  environment: "dev" | "staging" | "prod";
  region: string;
  ecsClusterName: string;
  ecsServiceName: string;
  cpuThreshold: number;
  memoryThreshold: number;
  alb5xxThreshold: number;
  alb4xxThreshold: number;
  responseTimeThreshold: number;
  slackWebhookUrl: string;
  alertEmail: string;
}

interface GeneratedCommand {
  id: string;
  label: string;
  description: string;
  command: string;
  phase: "prerequisite" | "deploy" | "verify" | "test";
  required: boolean;
}

// ─── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: DeploymentConfig = {
  environment: "dev",
  region: "us-east-1",
  ecsClusterName: "ac3-dev",
  ecsServiceName: "ac3-dev-caldera-dashboard",
  cpuThreshold: 80,
  memoryThreshold: 85,
  alb5xxThreshold: 10,
  alb4xxThreshold: 50,
  responseTimeThreshold: 3,
  slackWebhookUrl: "",
  alertEmail: "",
};

// ─── Command Generator ─────────────────────────────────────────────────────────

function generateDeployCommands(config: DeploymentConfig): GeneratedCommand[] {
  const stackName = `ac3-${config.environment}-monitoring`;
  const commands: GeneratedCommand[] = [];

  // Phase 1: Prerequisites
  commands.push({
    id: "check-aws-cli",
    label: "Verify AWS CLI",
    description: "Ensure AWS CLI v2 is installed and configured",
    command: `aws --version && aws sts get-caller-identity --region ${config.region}`,
    phase: "prerequisite",
    required: true,
  });

  commands.push({
    id: "check-ecs",
    label: "Verify ECS Service",
    description: "Confirm the ECS cluster and service are running",
    command: `aws ecs describe-services \\
  --cluster ${config.ecsClusterName} \\
  --services ${config.ecsServiceName} \\
  --region ${config.region} \\
  --query "services[0].{status:status,running:runningCount,desired:desiredCount}" \\
  --output table`,
    phase: "prerequisite",
    required: true,
  });

  commands.push({
    id: "discover-alb",
    label: "Discover ALB",
    description: "Find the Application Load Balancer for this environment",
    command: `aws elbv2 describe-load-balancers \\
  --region ${config.region} \\
  --query "LoadBalancers[?contains(LoadBalancerName, 'ac3-${config.environment}')].[LoadBalancerName,DNSName,State.Code]" \\
  --output table`,
    phase: "prerequisite",
    required: true,
  });

  // Phase 2: Deploy
  const deployArgs = [
    `./infrastructure/scripts/deploy-monitoring.sh \\`,
    `  --env ${config.environment} \\`,
    `  --region ${config.region}`,
  ];
  if (config.slackWebhookUrl) {
    deployArgs[deployArgs.length - 1] += " \\";
    deployArgs.push(`  --slack-webhook "${config.slackWebhookUrl}"`);
  }
  if (config.alertEmail) {
    deployArgs[deployArgs.length - 1] += " \\";
    deployArgs.push(`  --email "${config.alertEmail}"`);
  }

  commands.push({
    id: "dry-run",
    label: "Dry Run",
    description: "Validate the template and preview parameters without deploying",
    command: deployArgs.join("\n").replace(/--region/, "--dry-run \\\n  --region"),
    phase: "deploy",
    required: false,
  });

  // Build env export block
  const envExports = [
    `export ENVIRONMENT=${config.environment}`,
    `export AWS_REGION=${config.region}`,
    `export ECS_CLUSTER_NAME=${config.ecsClusterName}`,
    `export ECS_SERVICE_NAME=${config.ecsServiceName}`,
    `export CPU_THRESHOLD=${config.cpuThreshold}`,
    `export MEMORY_THRESHOLD=${config.memoryThreshold}`,
    `export ALB_5XX_THRESHOLD=${config.alb5xxThreshold}`,
    `export ALB_4XX_THRESHOLD=${config.alb4xxThreshold}`,
    `export RESPONSE_TIME_THRESHOLD=${config.responseTimeThreshold}`,
  ];
  if (config.slackWebhookUrl) {
    envExports.push(`export SLACK_WEBHOOK_URL="${config.slackWebhookUrl}"`);
  }
  if (config.alertEmail) {
    envExports.push(`export ALERT_EMAIL="${config.alertEmail}"`);
  }

  commands.push({
    id: "set-env",
    label: "Set Environment Variables",
    description: "Export all configuration as environment variables",
    command: envExports.join("\n"),
    phase: "deploy",
    required: true,
  });

  commands.push({
    id: "deploy-stack",
    label: "Deploy Monitoring Stack",
    description: "Run the deployment script to create/update the CloudFormation stack",
    command: deployArgs.join("\n"),
    phase: "deploy",
    required: true,
  });

  // Phase 3: Verify
  commands.push({
    id: "check-stack",
    label: "Check Stack Status",
    description: "Verify the CloudFormation stack deployed successfully",
    command: `aws cloudformation describe-stacks \\
  --stack-name ${stackName} \\
  --region ${config.region} \\
  --query "Stacks[0].{Status:StackStatus,Created:CreationTime,Updated:LastUpdatedTime}" \\
  --output table`,
    phase: "verify",
    required: true,
  });

  commands.push({
    id: "list-alarms",
    label: "List CloudWatch Alarms",
    description: "View all alarms created by the monitoring stack",
    command: `aws cloudwatch describe-alarms \\
  --alarm-name-prefix "ac3-${config.environment}-caldera-dashboard" \\
  --region ${config.region} \\
  --query "MetricAlarms[].[AlarmName,StateValue,MetricName]" \\
  --output table`,
    phase: "verify",
    required: true,
  });

  commands.push({
    id: "view-dashboard",
    label: "Open CloudWatch Dashboard",
    description: "View the monitoring dashboard in AWS Console",
    command: `echo "Dashboard URL:"
echo "https://${config.region}.console.aws.amazon.com/cloudwatch/home?region=${config.region}#dashboards:name=ac3-caldera-dashboard-${config.environment}"`,
    phase: "verify",
    required: false,
  });

  // Phase 4: Test
  commands.push({
    id: "test-alarm",
    label: "Test Alarm (Manual Trigger)",
    description: "Manually trigger a test alarm to verify notifications work",
    command: `# Trigger test alarm
aws cloudwatch set-alarm-state \\
  --alarm-name "ac3-caldera-dashboard-${config.environment}-ecs-cpu-high" \\
  --state-value ALARM \\
  --state-reason "Manual test — verifying notification pipeline" \\
  --region ${config.region}

# Wait 30 seconds, then check Slack/email for notification
sleep 30

# Reset alarm
aws cloudwatch set-alarm-state \\
  --alarm-name "ac3-caldera-dashboard-${config.environment}-ecs-cpu-high" \\
  --state-value OK \\
  --state-reason "Test complete — resetting to OK" \\
  --region ${config.region}`,
    phase: "test",
    required: false,
  });

  commands.push({
    id: "view-stack-outputs",
    label: "View Stack Outputs",
    description: "Show all outputs from the deployed stack (SNS topic ARN, dashboard URL, etc.)",
    command: `aws cloudformation describe-stacks \\
  --stack-name ${stackName} \\
  --region ${config.region} \\
  --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" \\
  --output table`,
    phase: "verify",
    required: false,
  });

  return commands;
}

// ─── What Gets Deployed ────────────────────────────────────────────────────────

const STACK_RESOURCES = [
  { type: "SNS Topic", name: "AlarmTopic", purpose: "Central notification routing for all alarms" },
  { type: "SNS Subscription", name: "Email Subscription", purpose: "Email notifications (if email configured)", conditional: true },
  { type: "Lambda Function", name: "Slack Notifier", purpose: "Formats and sends alarm notifications to Slack", conditional: true },
  { type: "CloudWatch Alarm", name: "ECS CPU High", purpose: "Triggers when CPU utilization exceeds threshold" },
  { type: "CloudWatch Alarm", name: "ECS Memory High", purpose: "Triggers when memory utilization exceeds threshold" },
  { type: "CloudWatch Alarm", name: "ECS No Running Tasks", purpose: "Triggers when service has zero running tasks" },
  { type: "CloudWatch Alarm", name: "ALB 5xx Errors", purpose: "Triggers on elevated server error rates", conditional: true },
  { type: "CloudWatch Alarm", name: "ALB 4xx Errors", purpose: "Triggers on elevated client error rates", conditional: true },
  { type: "CloudWatch Alarm", name: "ALB Response Time", purpose: "Triggers when response time exceeds threshold", conditional: true },
  { type: "CloudWatch Alarm", name: "Unhealthy Hosts", purpose: "Triggers when target group has unhealthy hosts", conditional: true },
  { type: "Metric Filter", name: "Application Errors", purpose: "Detects error-level log entries" },
  { type: "Metric Filter", name: "Fatal Errors", purpose: "Detects fatal/crash log entries" },
  { type: "Metric Filter", name: "Slow Requests", purpose: "Detects requests exceeding 5s response time" },
  { type: "CloudWatch Alarm", name: "App Error Rate", purpose: "Triggers on elevated application error rate" },
  { type: "CloudWatch Alarm", name: "Fatal Errors", purpose: "Triggers on any fatal error or crash" },
  { type: "Log Group", name: "Application Logs", purpose: "Centralized log group with retention policy" },
  { type: "CloudWatch Dashboard", name: "Monitoring Dashboard", purpose: "Single-pane view of all ECS + ALB metrics" },
];

// ─── Router ────────────────────────────────────────────────────────────────────

export const monitoringDeployRouter = router({
  /**
   * Get the default deployment configuration
   */
  getDefaultConfig: protectedProcedure.query(() => {
    return DEFAULT_CONFIG;
  }),

  /**
   * Generate deployment commands from user configuration
   */
  generateCommands: protectedProcedure
    .input(
      z.object({
        environment: z.enum(["dev", "staging", "prod"]),
        region: z.string().default("us-east-1"),
        ecsClusterName: z.string().optional(),
        ecsServiceName: z.string().optional(),
        cpuThreshold: z.number().min(1).max(100).default(80),
        memoryThreshold: z.number().min(1).max(100).default(85),
        alb5xxThreshold: z.number().min(1).default(10),
        alb4xxThreshold: z.number().min(1).default(50),
        responseTimeThreshold: z.number().min(0.1).default(3),
        slackWebhookUrl: z.string().default(""),
        alertEmail: z.string().default(""),
      })
    )
    .mutation(({ input }) => {
      const config: DeploymentConfig = {
        environment: input.environment,
        region: input.region,
        ecsClusterName: input.ecsClusterName || `ac3-${input.environment}`,
        ecsServiceName: input.ecsServiceName || `ac3-${input.environment}-caldera-dashboard`,
        cpuThreshold: input.cpuThreshold,
        memoryThreshold: input.memoryThreshold,
        alb5xxThreshold: input.alb5xxThreshold,
        alb4xxThreshold: input.alb4xxThreshold,
        responseTimeThreshold: input.responseTimeThreshold,
        slackWebhookUrl: input.slackWebhookUrl,
        alertEmail: input.alertEmail,
      };

      const commands = generateDeployCommands(config);

      return {
        config,
        commands,
        stackName: `ac3-${config.environment}-monitoring`,
        estimatedResources: STACK_RESOURCES.length,
      };
    }),

  /**
   * Get the list of resources that will be deployed
   */
  getStackResources: protectedProcedure.query(() => {
    return STACK_RESOURCES;
  }),

  /**
   * Get the raw CloudFormation template content
   */
  getTemplate: protectedProcedure.query(() => {
    const templatePath = join(process.cwd(), "infrastructure", "cloudformation", "ac3-monitoring.yaml");
    if (!existsSync(templatePath)) {
      return { found: false, content: "", path: templatePath };
    }
    const content = readFileSync(templatePath, "utf-8");
    return { found: true, content, path: templatePath };
  }),

  /**
   * Get the deploy script content
   */
  getDeployScript: protectedProcedure.query(() => {
    const scriptPath = join(process.cwd(), "infrastructure", "scripts", "deploy-monitoring.sh");
    if (!existsSync(scriptPath)) {
      return { found: false, content: "", path: scriptPath };
    }
    const content = readFileSync(scriptPath, "utf-8");
    return { found: true, content, path: scriptPath };
  }),

  /**
   * Get the environment template
   */
  getEnvTemplate: protectedProcedure.query(() => {
    const templatePath = join(process.cwd(), "infrastructure", "scripts", ".env.monitoring.template");
    if (!existsSync(templatePath)) {
      return { found: false, content: "", path: templatePath };
    }
    const content = readFileSync(templatePath, "utf-8");
    return { found: true, content, path: templatePath };
  }),

  /**
   * Validate a deployment configuration
   */
  validateConfig: protectedProcedure
    .input(
      z.object({
        environment: z.enum(["dev", "staging", "prod"]),
        region: z.string(),
        ecsClusterName: z.string(),
        ecsServiceName: z.string(),
        cpuThreshold: z.number(),
        memoryThreshold: z.number(),
        slackWebhookUrl: z.string().optional(),
        alertEmail: z.string().optional(),
      })
    )
    .mutation(({ input }) => {
      const issues: { field: string; message: string; severity: "error" | "warning" }[] = [];

      // Validate region format
      if (!/^[a-z]{2}-[a-z]+-\d$/.test(input.region)) {
        issues.push({ field: "region", message: "Invalid AWS region format", severity: "error" });
      }

      // Validate thresholds
      if (input.cpuThreshold > 95) {
        issues.push({ field: "cpuThreshold", message: "CPU threshold above 95% may not trigger in time", severity: "warning" });
      }
      if (input.memoryThreshold > 95) {
        issues.push({ field: "memoryThreshold", message: "Memory threshold above 95% risks OOM before alarm", severity: "warning" });
      }

      // Validate Slack webhook
      if (input.slackWebhookUrl && !input.slackWebhookUrl.startsWith("https://hooks.slack.com/")) {
        issues.push({ field: "slackWebhookUrl", message: "Slack webhook URL should start with https://hooks.slack.com/", severity: "warning" });
      }

      // Validate email
      if (input.alertEmail && !input.alertEmail.includes("@")) {
        issues.push({ field: "alertEmail", message: "Invalid email address format", severity: "error" });
      }

      // Check notification channels
      if (!input.slackWebhookUrl && !input.alertEmail) {
        issues.push({ field: "notifications", message: "No notification channel configured — alarms will fire but nobody will be notified", severity: "warning" });
      }

      // Production warnings
      if (input.environment === "prod") {
        if (input.cpuThreshold > 80) {
          issues.push({ field: "cpuThreshold", message: "Production CPU threshold above 80% is aggressive", severity: "warning" });
        }
        if (!input.slackWebhookUrl && !input.alertEmail) {
          issues.push({ field: "notifications", message: "Production deployment without notifications is strongly discouraged", severity: "error" });
        }
      }

      return {
        valid: issues.filter(i => i.severity === "error").length === 0,
        issues,
      };
    }),
});
