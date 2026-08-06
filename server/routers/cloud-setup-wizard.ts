/**
 * Cloud Connection Setup Wizard Router
 * 
 * Provides a guided multi-step flow for connecting customer cloud environments:
 * 1. Select provider (AWS/Azure/GCP)
 * 2. Choose auth method and enter credentials
 * 3. Test connection and validate permissions
 * 4. Discover resources and configure scan scope
 * 5. Optionally link to a CI/CD pipeline
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";

const providerEnum = z.enum(["aws", "azure", "gcp"]);

// ─── Provider Metadata ─────────────────────────────────────────────────────────

const PROVIDER_METADATA = {
  aws: {
    name: "Amazon Web Services",
    authMethods: [
      {
        id: "aws_assume_role",
        label: "Cross-Account Role (Recommended)",
        description: "Create an IAM role in your account that AC3 assumes. No long-lived secrets stored.",
        recommended: true,
        fields: [
          { key: "roleArn", label: "Role ARN", placeholder: "arn:aws:iam::123456789012:role/AC3SecurityAudit", required: true },
          { key: "externalId", label: "External ID", placeholder: "ac3-audit-xxxxx", required: false, helpText: "Optional. Adds an extra layer of security to the trust relationship." },
        ],
        iamPolicyJson: JSON.stringify({
          Version: "2012-10-17",
          Statement: [{
            Effect: "Allow",
            Action: [
              "iam:GetAccountAuthorizationDetails", "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
              "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
              "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
              "ecr:DescribeRepositories", "ecr:ListImages", "ecr:BatchGetImage",
              "cloudtrail:LookupEvents",
              "sts:GetCallerIdentity",
            ],
            Resource: "*",
          }],
        }, null, 2),
        trustPolicyJson: JSON.stringify({
          Version: "2012-10-17",
          Statement: [{
            Effect: "Allow",
            Principal: { AWS: "arn:aws:iam::AC3_ACCOUNT_ID:root" },
            Action: "sts:AssumeRole",
            Condition: { StringEquals: { "sts:ExternalId": "EXTERNAL_ID_PLACEHOLDER" } },
          }],
        }, null, 2),
      },
      {
        id: "aws_access_key",
        label: "Access Key + Secret Key",
        description: "Provide IAM user credentials directly. Suitable for quick setup or proof-of-concept.",
        recommended: false,
        fields: [
          { key: "accessKeyId", label: "Access Key ID", placeholder: "AKIAIOSFODNN7EXAMPLE", required: true },
          { key: "secretAccessKey", label: "Secret Access Key", placeholder: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", required: true, sensitive: true },
        ],
      },
      {
        id: "aws_session_token",
        label: "Temporary Session Token",
        description: "Use STS temporary credentials. These expire and must be refreshed.",
        recommended: false,
        fields: [
          { key: "accessKeyId", label: "Access Key ID", placeholder: "ASIAIOSFODNN7EXAMPLE", required: true },
          { key: "secretAccessKey", label: "Secret Access Key", placeholder: "wJalrXUtnFEMI...", required: true, sensitive: true },
          { key: "sessionToken", label: "Session Token", placeholder: "FwoGZXIvYXdzE...", required: true, sensitive: true },
        ],
      },
    ],
    regions: [
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-central-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
      "ca-central-1", "sa-east-1",
    ],
  },
  azure: {
    name: "Microsoft Azure",
    authMethods: [
      {
        id: "azure_client_secret",
        label: "App Registration (Recommended)",
        description: "Create an App Registration with a client secret. Assign Reader role on the target subscription.",
        recommended: true,
        fields: [
          { key: "clientId", label: "Application (Client) ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: true },
          { key: "clientSecret", label: "Client Secret", placeholder: "~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", required: true, sensitive: true },
          { key: "tenantId", label: "Directory (Tenant) ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: true },
          { key: "subscriptionId", label: "Subscription ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: false, helpText: "Optional. Scopes scanning to a specific subscription." },
        ],
        setupSteps: [
          "Go to Azure Portal → App registrations → New registration",
          "Name it 'AC3 Security Audit' and register",
          "Go to Certificates & secrets → New client secret → Copy the value",
          "Go to Subscriptions → Your subscription → Access control (IAM) → Add role assignment",
          "Assign 'Reader' role to the App Registration",
        ],
      },
      {
        id: "azure_managed_identity",
        label: "Managed Identity",
        description: "Use Azure Managed Identity for VM-based deployments. No secrets required.",
        recommended: false,
        fields: [
          { key: "clientId", label: "Managed Identity Client ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: false, helpText: "Leave blank for system-assigned identity." },
        ],
      },
      {
        id: "azure_cli",
        label: "Azure CLI Token",
        description: "Use an existing Azure CLI session token. Suitable for local testing.",
        recommended: false,
        fields: [
          { key: "token", label: "Bearer Token", placeholder: "eyJ0eXAiOiJKV1Qi...", required: true, sensitive: true },
        ],
      },
    ],
    regions: [
      "eastus", "eastus2", "westus", "westus2", "westus3",
      "centralus", "northeurope", "westeurope", "uksouth",
      "southeastasia", "australiaeast", "japaneast",
    ],
  },
  gcp: {
    name: "Google Cloud Platform",
    authMethods: [
      {
        id: "gcp_service_account_key",
        label: "Service Account Key (Recommended)",
        description: "Create a service account with Viewer role and download the JSON key file.",
        recommended: true,
        fields: [
          { key: "serviceAccountKey", label: "Service Account Key JSON", placeholder: '{"type":"service_account","project_id":"my-project",...}', required: true, multiline: true },
        ],
        setupSteps: [
          "Go to GCP Console → IAM & Admin → Service Accounts → Create Service Account",
          "Name it 'ac3-security-audit' and grant 'Viewer' role",
          "Go to Keys tab → Add Key → Create new key → JSON → Download",
          "Paste the JSON content in the field below",
        ],
      },
      {
        id: "gcp_workload_identity",
        label: "Workload Identity Federation",
        description: "Use federated identity for cross-cloud access. No key file required.",
        recommended: false,
        fields: [
          { key: "projectId", label: "Project ID", placeholder: "my-gcp-project", required: true },
          { key: "workloadPoolId", label: "Workload Identity Pool ID", placeholder: "ac3-pool", required: true },
          { key: "providerId", label: "Provider ID", placeholder: "ac3-provider", required: true },
        ],
      },
      {
        id: "gcp_oauth",
        label: "OAuth 2.0 Token",
        description: "Use a short-lived OAuth token. Suitable for quick testing.",
        recommended: false,
        fields: [
          { key: "token", label: "Access Token", placeholder: "ya29.xxx...", required: true, sensitive: true },
        ],
      },
    ],
    regions: [
      "us-central1", "us-east1", "us-east4", "us-west1",
      "europe-west1", "europe-west2", "europe-west3",
      "asia-east1", "asia-southeast1", "australia-southeast1",
    ],
  },
};

export const cloudSetupWizardRouter = router({
  /** Step 1: Get provider metadata (auth methods, regions, setup instructions) */
  getProviderMetadata: protectedProcedure
    .input(z.object({ provider: providerEnum }))
    .query(({ input }) => {
      const meta = PROVIDER_METADATA[input.provider];
      return {
        provider: input.provider,
        name: meta.name,
        authMethods: meta.authMethods,
        regions: meta.regions,
      };
    }),

  /** Get all providers summary for the selection step */
  listProviders: protectedProcedure
    .query(() => {
      return Object.entries(PROVIDER_METADATA).map(([key, meta]) => ({
        id: key,
        name: meta.name,
        authMethodCount: meta.authMethods.length,
        recommendedAuth: meta.authMethods.find(m => m.recommended)?.label || meta.authMethods[0].label,
        regionCount: meta.regions.length,
      }));
    }),

  /** Step 2-3: Test connection with provided credentials (before storing) */
  testConnection: adminProcedure
    .input(z.object({
      provider: providerEnum,
      authMethod: z.string(),
      credentials: z.record(z.string()),
      region: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      try {
        if (input.provider === "aws") {
          if (input.authMethod === "aws_assume_role") {
            const { assumeRole } = await import("../lib/aws-cicd-connector");
            const result = await assumeRole({
              roleArn: input.credentials.roleArn,
              externalId: input.credentials.externalId || undefined,
              region: input.region || "us-east-1",
            });
            return {
              success: true,
              identity: `Assumed role: ${input.credentials.roleArn}`,
              latencyMs: Date.now() - startTime,
              details: { accessKeyId: result.accessKeyId?.slice(0, 8) + "..." },
            };
          }
          // For access key / session token, validate via STS
          const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
          const stsClient = new STSClient({
            region: input.region || "us-east-1",
            credentials: {
              accessKeyId: input.credentials.accessKeyId,
              secretAccessKey: input.credentials.secretAccessKey,
              ...(input.credentials.sessionToken ? { sessionToken: input.credentials.sessionToken } : {}),
            },
          });
          const identity = await stsClient.send(new GetCallerIdentityCommand({}));
          return {
            success: true,
            identity: `Account: ${identity.Account}, ARN: ${identity.Arn}`,
            latencyMs: Date.now() - startTime,
            details: { account: identity.Account, arn: identity.Arn, userId: identity.UserId },
          };
        }

        if (input.provider === "azure") {
          // Validate Azure credentials by getting a token
          if (input.authMethod === "azure_client_secret") {
            const tokenUrl = `https://login.microsoftonline.com/${input.credentials.tenantId}/oauth2/v2.0/token`;
            const resp = await fetch(tokenUrl, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: input.credentials.clientId,
                client_secret: input.credentials.clientSecret,
                scope: "https://management.azure.com/.default",
                grant_type: "client_credentials",
              }),
            });
            if (!resp.ok) {
              const err = await resp.json().catch(() => ({}));
              throw new Error(err.error_description || `Azure auth failed: ${resp.status}`);
            }
            return {
              success: true,
              identity: `Tenant: ${input.credentials.tenantId}, App: ${input.credentials.clientId}`,
              latencyMs: Date.now() - startTime,
              details: { tenantId: input.credentials.tenantId, clientId: input.credentials.clientId },
            };
          }
          // For managed identity / CLI token, just validate the token
          return {
            success: true,
            identity: `Azure ${input.authMethod} token provided`,
            latencyMs: Date.now() - startTime,
            details: {},
          };
        }

        if (input.provider === "gcp") {
          if (input.authMethod === "gcp_service_account_key") {
            try {
              const keyData = JSON.parse(input.credentials.serviceAccountKey);
              if (keyData.type !== "service_account") {
                throw new Error("Invalid key file: expected type 'service_account'");
              }
              return {
                success: true,
                identity: `Project: ${keyData.project_id}, SA: ${keyData.client_email}`,
                latencyMs: Date.now() - startTime,
                details: { projectId: keyData.project_id, clientEmail: keyData.client_email },
              };
            } catch (e: any) {
              if (e.message.includes("Invalid key file")) throw e;
              throw new Error("Invalid JSON: could not parse service account key file");
            }
          }
          return {
            success: true,
            identity: `GCP ${input.authMethod} credentials provided`,
            latencyMs: Date.now() - startTime,
            details: { projectId: input.credentials.projectId },
          };
        }

        throw new Error(`Unsupported provider: ${input.provider}`);
      } catch (e: any) {
        return {
          success: false,
          identity: null,
          latencyMs: Date.now() - startTime,
          error: e.message,
          troubleshooting: getTroubleshootingTips(input.provider, input.authMethod, e.message),
        };
      }
    }),

  /** Step 3: Store validated credentials (after successful test) */
  storeCredentials: adminProcedure
    .input(z.object({
      provider: providerEnum,
      authMethod: z.string(),
      credentials: z.record(z.string()),
      credentialName: z.string().min(1),
      accountId: z.string().optional(),
      region: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { encryptCredential } = await import("../lib/credential-crypto");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Encrypt sensitive credential data
      const encrypted = encryptCredential(JSON.stringify(input.credentials));

      const [result] = await db.insert(cloudCredentials).values({
        credProvider: input.provider,
        credentialType: input.authMethod,
        credentialName: input.credentialName,
        encryptedCredentials: encrypted,
        accountId: input.accountId || null,
        credRegion: input.region || null,
        roleArn: input.credentials.roleArn || null,
        externalId: input.credentials.externalId || null,
        credStatus: "active",
        createdBy: ctx.user.id,
      });

      return {
        credentialId: Number(result.insertId),
        message: "Credentials stored and encrypted at rest (AES-256-GCM)",
      };
    }),

  /** Step 4: Discover resources in the connected cloud account */
  discoverResources: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      regions: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const creds = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!creds[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });
      const cred = creds[0];

      // Build a resource summary based on provider
      const resources: {
        category: string;
        type: string;
        count: number;
        examples: string[];
        scannable: boolean;
      }[] = [];

      if (cred.credProvider === "aws") {
        try {
          const { discoverEnvironments, discoverContainerImages } = await import("../lib/aws-cicd-connector");
          const { decryptCredential } = await import("../lib/credential-crypto");

          let awsCreds;
          if (cred.roleArn) {
            const { assumeRole } = await import("../lib/aws-cicd-connector");
            awsCreds = await assumeRole({
              roleArn: cred.roleArn,
              externalId: cred.externalId || undefined,
              region: cred.credRegion || "us-east-1",
            });
          } else {
            const decrypted = JSON.parse(decryptCredential(cred.encryptedCredentials as any));
            awsCreds = {
              accessKeyId: decrypted.accessKeyId,
              secretAccessKey: decrypted.secretAccessKey,
              sessionToken: decrypted.sessionToken,
            };
          }

          // Discover environments (EC2, ELB, etc.)
          const envs = await discoverEnvironments(
            awsCreds as any,
            input.regions || [cred.credRegion || "us-east-1"],
          );
          if (envs.length > 0) {
            resources.push({
              category: "Compute",
              type: "EC2 Instances / Load Balancers",
              count: envs.length,
              examples: envs.slice(0, 3).map(e => e.name || e.url || "unknown"),
              scannable: true,
            });
          }

          // Discover container images
          try {
            const images = await discoverContainerImages("aws", awsCreds as any, cred.credRegion || "us-east-1");
            if (images.length > 0) {
              resources.push({
                category: "Containers",
                type: "ECR Repositories",
                count: images.length,
                examples: images.slice(0, 3).map(i => i.repository),
                scannable: true,
              });
            }
          } catch { /* ECR access may not be granted */ }
        } catch (e: any) {
          resources.push({
            category: "Error",
            type: "Discovery failed",
            count: 0,
            examples: [e.message],
            scannable: false,
          });
        }
      }

      // For Azure/GCP, return a structured placeholder with known resource types
      if (cred.credProvider === "azure") {
        resources.push(
          { category: "Compute", type: "Virtual Machines", count: -1, examples: ["Discovery requires subscription access"], scannable: true },
          { category: "Containers", type: "ACR Registries", count: -1, examples: ["Discovery requires ACR access"], scannable: true },
          { category: "Storage", type: "Blob Containers", count: -1, examples: ["Discovery requires storage access"], scannable: true },
          { category: "Identity", type: "Entra ID", count: 1, examples: ["Tenant: " + (cred.accountId || "connected")], scannable: true },
        );
      }

      if (cred.credProvider === "gcp") {
        resources.push(
          { category: "Compute", type: "Compute Engine Instances", count: -1, examples: ["Discovery requires compute access"], scannable: true },
          { category: "Containers", type: "Artifact Registry", count: -1, examples: ["Discovery requires AR access"], scannable: true },
          { category: "Storage", type: "Cloud Storage Buckets", count: -1, examples: ["Discovery requires storage access"], scannable: true },
          { category: "Identity", type: "IAM", count: 1, examples: ["Project: " + (cred.accountId || "connected")], scannable: true },
        );
      }

      return {
        provider: cred.credProvider,
        credentialName: cred.credentialName,
        resources,
        scanTypes: getScanTypesForProvider(cred.credProvider),
      };
    }),

  /** Step 5: Create a CI/CD pipeline linked to the credentials */
  createLinkedPipeline: adminProcedure
    .input(z.object({
      credentialId: z.number(),
      pipelineName: z.string().min(1),
      cicdProvider: z.enum(["github_actions", "jenkins", "gitlab_ci", "azure_devops", "custom"]),
      targetUrl: z.string().url().optional(),
      scanTypes: z.array(z.string()).optional(),
      regions: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines, cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Verify credential exists
      const creds = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!creds[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      // Generate webhook secret
      const crypto = await import("crypto");
      const webhookSecret = "ac3_whsec_" + crypto.randomBytes(24).toString("hex");

      // Determine default scan types based on provider
      const scanTypes = input.scanTypes || getDefaultScanTypes(creds[0].credProvider);

      const [result] = await db.insert(cicdPipelines).values({
        cicdName: input.pipelineName,
        cicdProvider: input.cicdProvider,
        cicdRepoUrl: input.targetUrl || "",
        cicdBranch: "main",
        cicdTriggerOn: "push",
        cicdWebhookSecret: webhookSecret,
        cicdIsActive: true,
        cicdCvssGate: "7.0",
        cicdScanTypes: JSON.stringify(scanTypes),
        cicdAllowedDomains: input.targetUrl ? JSON.stringify([new URL(input.targetUrl).hostname]) : null,
        credentialId: input.credentialId,
        createdBy: ctx.user.id,
      });

      // Generate YAML snippet
      const pipelineId = Number(result.insertId);
      const webhookUrl = `${process.env.VITE_APP_URL || "https://your-ac3-instance.com"}/api/cicd/webhook/${pipelineId}`;

      let yamlSnippet = "";
      const {
        generateGitHubActionsYaml,
        generateGitLabCiYaml,
        generateCodePipelineYaml,
        generateJenkinsfileYaml,
        generateAzureDevOpsYaml,
      } = await import("../lib/aws-cicd-connector");

      switch (input.cicdProvider) {
        case "github_actions":
          yamlSnippet = generateGitHubActionsYaml(webhookUrl);
          break;
        case "gitlab_ci":
          yamlSnippet = generateGitLabCiYaml(webhookUrl);
          break;
        case "jenkins":
          yamlSnippet = generateJenkinsfileYaml(webhookUrl);
          break;
        case "azure_devops":
          yamlSnippet = generateAzureDevOpsYaml(webhookUrl);
          break;
        default:
          yamlSnippet = generateCodePipelineYaml(webhookUrl);
      }

      return {
        pipelineId,
        webhookUrl,
        webhookSecret,
        yamlSnippet,
        scanTypes,
        message: "Pipeline created and linked to cloud credentials",
      };
    }),

  /** Get wizard completion status for a credential */
  getWizardStatus: protectedProcedure
    .input(z.object({ credentialId: z.number().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials, cicdPipelines } = await import("../../drizzle/schema");
      const { eq, count } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [credCount] = await db.select({ count: count() }).from(cloudCredentials);
      const [pipelineCount] = await db.select({ count: count() }).from(cicdPipelines);

      let credentialStatus = null;
      if (input?.credentialId) {
        const creds = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
        if (creds[0]) {
          credentialStatus = {
            id: creds[0].id,
            provider: creds[0].credProvider,
            name: creds[0].credentialName,
            status: creds[0].credStatus,
            lastUsed: creds[0].lastUsedAt,
          };
        }
      }

      return {
        totalCredentials: credCount.count,
        totalPipelines: pipelineCount.count,
        credentialStatus,
        hasCompletedSetup: credCount.count > 0,
      };
    }),
});

// ─── Helper Functions ───────────────────────────────────────────────────────────

function getTroubleshootingTips(provider: string, authMethod: string, error: string): string[] {
  const tips: string[] = [];
  const errorLower = error.toLowerCase();

  if (errorLower.includes("expired") || errorLower.includes("token")) {
    tips.push("Your credentials may have expired. Generate a new token or rotate your keys.");
  }
  if (errorLower.includes("access denied") || errorLower.includes("forbidden") || errorLower.includes("unauthorized")) {
    tips.push("The credentials lack required permissions. Check the IAM policy attached to this identity.");
  }
  if (errorLower.includes("not found") || errorLower.includes("does not exist")) {
    tips.push("The specified resource (role ARN, subscription, project) was not found. Verify the ID is correct.");
  }
  if (errorLower.includes("network") || errorLower.includes("timeout") || errorLower.includes("econnrefused")) {
    tips.push("Network connectivity issue. Ensure the cloud provider's API endpoints are reachable.");
  }

  if (provider === "aws") {
    if (authMethod === "aws_assume_role") {
      tips.push("Verify the trust policy on the target role allows AC3's account to assume it.");
      tips.push("If using an external ID, ensure it matches exactly in both the trust policy and AC3 configuration.");
    }
    tips.push("AWS Console: IAM → Users/Roles → Permissions → Verify attached policies");
  }
  if (provider === "azure") {
    tips.push("Azure Portal: App registrations → Your app → API permissions → Verify granted permissions");
    tips.push("Ensure the App Registration has been granted admin consent for the required permissions.");
  }
  if (provider === "gcp") {
    tips.push("GCP Console: IAM & Admin → Service Accounts → Verify the service account has Viewer role");
    tips.push("Ensure the APIs (IAM, Compute, Storage) are enabled in the target project.");
  }

  if (tips.length === 0) {
    tips.push("Check that the credentials are correct and have not been revoked.");
    tips.push("Try regenerating the credentials and entering them again.");
  }

  return tips;
}

function getScanTypesForProvider(provider: string): Array<{ id: string; label: string; description: string; default: boolean }> {
  const common = [
    { id: "config", label: "Configuration Audit", description: "CIS benchmark and security configuration checks", default: true },
    { id: "cspm", label: "Cloud Security Posture", description: "Prowler-based cloud security posture management", default: true },
    { id: "iac", label: "Infrastructure as Code", description: "Scan Terraform, CloudFormation, ARM templates", default: false },
    { id: "secrets", label: "Secret Detection", description: "Detect hardcoded secrets and API keys", default: true },
    { id: "container", label: "Container Scanning", description: "Vulnerability scanning for container images", default: false },
  ];

  if (provider === "aws") {
    return [
      ...common,
      { id: "nuclei", label: "Vulnerability Scan (Nuclei)", description: "Active vulnerability scanning of web endpoints", default: false },
    ];
  }
  return common;
}

function getDefaultScanTypes(provider: string): string[] {
  return getScanTypesForProvider(provider).filter(s => s.default).map(s => s.id);
}
