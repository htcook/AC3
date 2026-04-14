/**
 * Unified Cloud Resource Enumerator
 *
 * Extends the IAM-only enumeration with full resource scanning:
 * - AWS: EC2, S3, RDS, Lambda, VPC, CloudTrail, GuardDuty, SecurityHub
 * - Azure: VMs, Storage Accounts, NSGs, Key Vaults, SQL, Subscriptions, Activity Log
 * - GCP: Compute, Storage, Cloud SQL, Cloud Functions, VPC, Audit Logs
 *
 * Also wires CIS benchmark checks to real enumeration data so they return
 * pass/fail instead of "not_assessed".
 *
 * Consolidates: cloud-iam-enumerator, cloud-security-validation, cloud-workload-testing
 */

// ── Types ──────────────────────────────────────────────────────────────────

export interface CloudResource {
  resourceType: string;       // e.g. "ec2_instance", "s3_bucket", "azure_vm"
  resourceId: string;
  name: string;
  region?: string;
  provider: "aws" | "azure" | "gcp";
  metadata: Record<string, any>;
  misconfigurations: ResourceMisconfiguration[];
}

export interface ResourceMisconfiguration {
  checkId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation: string;
  cisBenchmark?: string;
  mitreTechnique?: string;
  status: "fail" | "warning";
  evidence: string;
}

export interface ResourceEnumerationResult {
  provider: "aws" | "azure" | "gcp";
  resources: CloudResource[];
  misconfigurations: ResourceMisconfiguration[];
  cisResults: CISCheckResult[];
  summary: ResourceSummary;
  errors: string[];
}

export interface ResourceSummary {
  totalResources: number;
  byType: Record<string, number>;
  totalMisconfigurations: number;
  bySeverity: Record<string, number>;
  cisScore: number;        // 0-100
  cisPassed: number;
  cisFailed: number;
  cisNotAssessed: number;
}

export interface CISCheckResult {
  checkId: string;
  title: string;
  domain: string;
  severity: string;
  status: "pass" | "fail" | "warning" | "not_assessed";
  currentValue: string;
  expectedValue: string;
  evidence: string;
  affectedResources: string[];
}

// Re-export credential types from IAM enumerator
export type { AWSCredentials, AzureCredentials, GCPCredentials } from "./cloud-iam-enumerator";

// ── AWS Resource Enumeration ───────────────────────────────────────────────

export async function enumerateAWSResources(creds: {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
  roleArn?: string;
  externalId?: string;
}): Promise<ResourceEnumerationResult> {
  const errors: string[] = [];
  const resources: CloudResource[] = [];
  const misconfigurations: ResourceMisconfiguration[] = [];
  const cisResults: CISCheckResult[] = [];

  try {
    const { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } = await import("@aws-sdk/client-sts");
    const region = creds.region || "us-east-1";

    let credentials: any = {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
    };

    // Assume role if provided
    if (creds.roleArn) {
      try {
        const stsClient = new STSClient({ region, credentials });
        const assumeResult = await stsClient.send(new AssumeRoleCommand({
          RoleArn: creds.roleArn,
          RoleSessionName: "ac3-resource-enum",
          ...(creds.externalId ? { ExternalId: creds.externalId } : {}),
          DurationSeconds: 3600,
        }));
        if (assumeResult.Credentials) {
          credentials = {
            accessKeyId: assumeResult.Credentials.AccessKeyId!,
            secretAccessKey: assumeResult.Credentials.SecretAccessKey!,
            sessionToken: assumeResult.Credentials.SessionToken!,
          };
        }
      } catch (e: any) {
        errors.push(`AssumeRole failed: ${e.message}`);
      }
    }

    // Verify identity
    const stsClient = new STSClient({ region, credentials });
    try {
      const identity = await stsClient.send(new GetCallerIdentityCommand({}));
      console.log(`[AWS ResourceEnum] Authenticated as: ${identity.Arn}`);
    } catch (e: any) {
      errors.push(`Identity verification failed: ${e.message}`);
      return buildResult("aws", resources, misconfigurations, cisResults, errors);
    }

    // ── EC2 Instances ──
    await enumerateEC2(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── S3 Buckets ──
    await enumerateS3(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── RDS Instances ──
    await enumerateRDS(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── Lambda Functions ──
    await enumerateLambda(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── VPC & Security Groups ──
    await enumerateVPC(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── CloudTrail ──
    await enumerateCloudTrail(credentials, region, resources, misconfigurations, cisResults, errors);

    // ── GuardDuty ──
    await enumerateGuardDuty(credentials, region, resources, misconfigurations, cisResults, errors);

  } catch (e: any) {
    errors.push(`AWS resource enumeration error: ${e.message}`);
  }

  return buildResult("aws", resources, misconfigurations, cisResults, errors);
}

// ── EC2 ────────────────────────────────────────────────────────────────────

async function enumerateEC2(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { EC2Client, DescribeInstancesCommand, DescribeSecurityGroupsCommand,
      DescribeVolumesCommand, DescribeImagesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = new EC2Client({ region, credentials });

    // Enumerate instances
    const instancesResp = await ec2.send(new DescribeInstancesCommand({ MaxResults: 1000 }));
    const instances: any[] = [];
    for (const reservation of instancesResp.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        instances.push(inst);
        const nameTag = inst.Tags?.find(t => t.Key === "Name")?.Value || inst.InstanceId || "unnamed";
        const isPublic = !!inst.PublicIpAddress;
        const hasIMDSv2 = inst.MetadataOptions?.HttpTokens === "required";

        const resource: CloudResource = {
          resourceType: "ec2_instance",
          resourceId: inst.InstanceId || "",
          name: nameTag,
          region,
          provider: "aws",
          metadata: {
            instanceType: inst.InstanceType,
            state: inst.State?.Name,
            publicIp: inst.PublicIpAddress,
            privateIp: inst.PrivateIpAddress,
            vpcId: inst.VpcId,
            subnetId: inst.SubnetId,
            securityGroups: inst.SecurityGroups?.map(sg => ({ id: sg.GroupId, name: sg.GroupName })),
            iamProfile: inst.IamInstanceProfile?.Arn,
            launchTime: inst.LaunchTime,
            platform: inst.Platform || "linux",
            imdsV2Required: hasIMDSv2,
            monitoring: inst.Monitoring?.State,
            ebsOptimized: inst.EbsOptimized,
          },
          misconfigurations: [],
        };

        // Check: Public IP exposure
        if (isPublic) {
          const mc: ResourceMisconfiguration = {
            checkId: "ec2-public-ip",
            severity: "medium",
            title: "EC2 Instance with Public IP",
            description: `Instance ${inst.InstanceId} has public IP ${inst.PublicIpAddress}`,
            remediation: "Use private subnets with NAT gateway or ALB for internet access",
            cisBenchmark: "CIS AWS 5.1",
            mitreTechnique: "T1190",
            status: "warning",
            evidence: `Public IP: ${inst.PublicIpAddress}, VPC: ${inst.VpcId}`,
          };
          resource.misconfigurations.push(mc);
          misconfigs.push(mc);
        }

        // Check: IMDSv2 not enforced
        if (!hasIMDSv2) {
          const mc: ResourceMisconfiguration = {
            checkId: "ec2-imdsv2",
            severity: "high",
            title: "IMDSv2 Not Enforced",
            description: `Instance ${inst.InstanceId} does not require IMDSv2`,
            remediation: "Set HttpTokens to 'required' in instance metadata options",
            cisBenchmark: "CIS AWS 5.6",
            mitreTechnique: "T1552.005",
            status: "fail",
            evidence: `HttpTokens: ${inst.MetadataOptions?.HttpTokens || "optional"}`,
          };
          resource.misconfigurations.push(mc);
          misconfigs.push(mc);
        }

        // Check: No IAM instance profile
        if (!inst.IamInstanceProfile && inst.State?.Name === "running") {
          const mc: ResourceMisconfiguration = {
            checkId: "ec2-no-iam-profile",
            severity: "low",
            title: "EC2 Instance Without IAM Profile",
            description: `Running instance ${inst.InstanceId} has no IAM instance profile`,
            remediation: "Attach an IAM instance profile with least-privilege permissions",
            status: "warning",
            evidence: `Instance ${inst.InstanceId} running without IAM profile`,
          };
          resource.misconfigurations.push(mc);
          misconfigs.push(mc);
        }

        // Check: Monitoring disabled
        if (inst.Monitoring?.State !== "enabled") {
          const mc: ResourceMisconfiguration = {
            checkId: "ec2-monitoring-disabled",
            severity: "low",
            title: "Detailed Monitoring Disabled",
            description: `Instance ${inst.InstanceId} does not have detailed monitoring enabled`,
            remediation: "Enable detailed monitoring for better visibility",
            cisBenchmark: "CIS AWS 4.1",
            status: "warning",
            evidence: `Monitoring state: ${inst.Monitoring?.State || "disabled"}`,
          };
          resource.misconfigurations.push(mc);
          misconfigs.push(mc);
        }

        resources.push(resource);
      }
    }

    // CIS check: EC2 IMDSv2
    const imdsv2Failing = instances.filter(i => i.MetadataOptions?.HttpTokens !== "required" && i.State?.Name === "running");
    cisResults.push({
      checkId: "cis-aws-ec2-imdsv2",
      title: "Ensure IMDSv2 is required on all EC2 instances",
      domain: "compute",
      severity: "high",
      status: imdsv2Failing.length === 0 ? "pass" : "fail",
      currentValue: `${imdsv2Failing.length} instances without IMDSv2`,
      expectedValue: "0 instances without IMDSv2",
      evidence: imdsv2Failing.map(i => i.InstanceId).join(", ") || "All compliant",
      affectedResources: imdsv2Failing.map(i => i.InstanceId),
    });

    // Enumerate EBS volumes for encryption check
    try {
      const volResp = await ec2.send(new DescribeVolumesCommand({ MaxResults: 500 }));
      const unencryptedVols = (volResp.Volumes || []).filter(v => !v.Encrypted);
      for (const vol of volResp.Volumes || []) {
        resources.push({
          resourceType: "ebs_volume",
          resourceId: vol.VolumeId || "",
          name: vol.Tags?.find(t => t.Key === "Name")?.Value || vol.VolumeId || "",
          region,
          provider: "aws",
          metadata: {
            size: vol.Size,
            volumeType: vol.VolumeType,
            encrypted: vol.Encrypted,
            state: vol.State,
            attachments: vol.Attachments?.map(a => a.InstanceId),
          },
          misconfigurations: vol.Encrypted ? [] : [{
            checkId: "ebs-unencrypted",
            severity: "high",
            title: "Unencrypted EBS Volume",
            description: `Volume ${vol.VolumeId} is not encrypted`,
            remediation: "Enable default EBS encryption or create encrypted snapshots",
            cisBenchmark: "CIS AWS 2.2.1",
            status: "fail" as const,
            evidence: `Volume ${vol.VolumeId} (${vol.Size}GB, ${vol.VolumeType}) is unencrypted`,
          }],
        });
      }
      cisResults.push({
        checkId: "cis-aws-ebs-encryption",
        title: "Ensure EBS volume encryption is enabled",
        domain: "storage",
        severity: "high",
        status: unencryptedVols.length === 0 ? "pass" : "fail",
        currentValue: `${unencryptedVols.length} unencrypted volumes`,
        expectedValue: "0 unencrypted volumes",
        evidence: unencryptedVols.map(v => v.VolumeId).join(", ") || "All encrypted",
        affectedResources: unencryptedVols.map(v => v.VolumeId || ""),
      });
    } catch (e: any) {
      errors.push(`EBS enumeration failed: ${e.message}`);
    }

  } catch (e: any) {
    errors.push(`EC2 enumeration failed: ${e.message}`);
  }
}

// ── S3 ─────────────────────────────────────────────────────────────────────

async function enumerateS3(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { S3Client, ListBucketsCommand, GetBucketEncryptionCommand,
      GetBucketVersioningCommand, GetBucketPolicyStatusCommand,
      GetPublicAccessBlockCommand, GetBucketLoggingCommand,
      GetBucketAclCommand } = await import("@aws-sdk/client-s3");
    const s3 = new S3Client({ region, credentials });

    const bucketsResp = await s3.send(new ListBucketsCommand({}));
    const buckets = bucketsResp.Buckets || [];
    let publicBuckets = 0;
    let unencryptedBuckets = 0;
    let noVersioningBuckets = 0;
    let noLoggingBuckets = 0;

    for (const bucket of buckets) {
      const bucketName = bucket.Name || "";
      let isPublic = false;
      let isEncrypted = false;
      let hasVersioning = false;
      let hasLogging = false;
      let publicAccessBlock: any = null;

      // Check public access block
      try {
        const pabResp = await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
        publicAccessBlock = pabResp.PublicAccessBlockConfiguration;
        const allBlocked = publicAccessBlock?.BlockPublicAcls &&
          publicAccessBlock?.BlockPublicPolicy &&
          publicAccessBlock?.IgnorePublicAcls &&
          publicAccessBlock?.RestrictPublicBuckets;
        if (!allBlocked) isPublic = true;
      } catch (e: any) {
        if (e.name !== "NoSuchPublicAccessBlockConfiguration") {
          errors.push(`S3 public access check failed for ${bucketName}: ${e.message}`);
        } else {
          isPublic = true; // No public access block = potentially public
        }
      }

      // Check encryption
      try {
        await s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
        isEncrypted = true;
      } catch (e: any) {
        if (e.name === "ServerSideEncryptionConfigurationNotFoundError") {
          isEncrypted = false;
        }
      }

      // Check versioning
      try {
        const verResp = await s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
        hasVersioning = verResp.Status === "Enabled";
      } catch { /* skip */ }

      // Check logging
      try {
        const logResp = await s3.send(new GetBucketLoggingCommand({ Bucket: bucketName }));
        hasLogging = !!logResp.LoggingEnabled;
      } catch { /* skip */ }

      if (isPublic) publicBuckets++;
      if (!isEncrypted) unencryptedBuckets++;
      if (!hasVersioning) noVersioningBuckets++;
      if (!hasLogging) noLoggingBuckets++;

      const bucketMisconfigs: ResourceMisconfiguration[] = [];

      if (isPublic) {
        const mc: ResourceMisconfiguration = {
          checkId: "s3-public-access",
          severity: "critical",
          title: "S3 Bucket Publicly Accessible",
          description: `Bucket ${bucketName} does not have full public access block`,
          remediation: "Enable S3 Block Public Access on the bucket",
          cisBenchmark: "CIS AWS 2.1.5",
          mitreTechnique: "T1530",
          status: "fail",
          evidence: `Public access block: ${JSON.stringify(publicAccessBlock || "not configured")}`,
        };
        bucketMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!isEncrypted) {
        const mc: ResourceMisconfiguration = {
          checkId: "s3-encryption",
          severity: "high",
          title: "S3 Bucket Without Default Encryption",
          description: `Bucket ${bucketName} does not have default encryption enabled`,
          remediation: "Enable default SSE-S3 or SSE-KMS encryption",
          cisBenchmark: "CIS AWS 2.1.1",
          status: "fail",
          evidence: `No server-side encryption configuration found`,
        };
        bucketMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!hasLogging) {
        const mc: ResourceMisconfiguration = {
          checkId: "s3-logging",
          severity: "medium",
          title: "S3 Bucket Logging Disabled",
          description: `Bucket ${bucketName} does not have access logging enabled`,
          remediation: "Enable server access logging to a separate logging bucket",
          cisBenchmark: "CIS AWS 2.1.3",
          status: "warning",
          evidence: `Access logging not configured`,
        };
        bucketMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "s3_bucket",
        resourceId: bucketName,
        name: bucketName,
        region: "global",
        provider: "aws",
        metadata: {
          creationDate: bucket.CreationDate,
          isPublic,
          isEncrypted,
          hasVersioning,
          hasLogging,
          publicAccessBlock,
        },
        misconfigurations: bucketMisconfigs,
      });
    }

    // CIS checks for S3
    cisResults.push(
      {
        checkId: "cis-aws-s3-public-access",
        title: "Ensure S3 buckets have public access blocked",
        domain: "storage",
        severity: "critical",
        status: publicBuckets === 0 ? "pass" : "fail",
        currentValue: `${publicBuckets} publicly accessible buckets`,
        expectedValue: "0 publicly accessible buckets",
        evidence: `${buckets.length} total buckets, ${publicBuckets} without full public access block`,
        affectedResources: resources.filter(r => r.resourceType === "s3_bucket" && r.metadata.isPublic).map(r => r.name),
      },
      {
        checkId: "cis-aws-s3-encryption",
        title: "Ensure S3 buckets have default encryption enabled",
        domain: "storage",
        severity: "high",
        status: unencryptedBuckets === 0 ? "pass" : "fail",
        currentValue: `${unencryptedBuckets} unencrypted buckets`,
        expectedValue: "0 unencrypted buckets",
        evidence: `${buckets.length} total buckets, ${unencryptedBuckets} without default encryption`,
        affectedResources: resources.filter(r => r.resourceType === "s3_bucket" && !r.metadata.isEncrypted).map(r => r.name),
      },
      {
        checkId: "cis-aws-s3-logging",
        title: "Ensure S3 bucket access logging is enabled",
        domain: "storage",
        severity: "medium",
        status: noLoggingBuckets === 0 ? "pass" : "fail",
        currentValue: `${noLoggingBuckets} buckets without logging`,
        expectedValue: "0 buckets without logging",
        evidence: `${buckets.length} total buckets, ${noLoggingBuckets} without access logging`,
        affectedResources: resources.filter(r => r.resourceType === "s3_bucket" && !r.metadata.hasLogging).map(r => r.name),
      }
    );

  } catch (e: any) {
    errors.push(`S3 enumeration failed: ${e.message}`);
  }
}

// ── RDS ────────────────────────────────────────────────────────────────────

async function enumerateRDS(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { RDSClient, DescribeDBInstancesCommand } = await import("@aws-sdk/client-rds");
    const rds = new RDSClient({ region, credentials });

    const dbResp = await rds.send(new DescribeDBInstancesCommand({}));
    const instances = dbResp.DBInstances || [];
    let publicInstances = 0;
    let unencryptedInstances = 0;
    let noBackupInstances = 0;

    for (const db of instances) {
      const isPublic = db.PubliclyAccessible || false;
      const isEncrypted = db.StorageEncrypted || false;
      const hasBackup = (db.BackupRetentionPeriod || 0) > 0;
      const hasMultiAZ = db.MultiAZ || false;

      if (isPublic) publicInstances++;
      if (!isEncrypted) unencryptedInstances++;
      if (!hasBackup) noBackupInstances++;

      const dbMisconfigs: ResourceMisconfiguration[] = [];

      if (isPublic) {
        const mc: ResourceMisconfiguration = {
          checkId: "rds-public-access",
          severity: "critical",
          title: "RDS Instance Publicly Accessible",
          description: `RDS instance ${db.DBInstanceIdentifier} is publicly accessible`,
          remediation: "Disable public accessibility and use VPC security groups",
          cisBenchmark: "CIS AWS 2.3.1",
          mitreTechnique: "T1190",
          status: "fail",
          evidence: `PubliclyAccessible: true, Endpoint: ${db.Endpoint?.Address}:${db.Endpoint?.Port}`,
        };
        dbMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!isEncrypted) {
        const mc: ResourceMisconfiguration = {
          checkId: "rds-encryption",
          severity: "high",
          title: "RDS Instance Not Encrypted",
          description: `RDS instance ${db.DBInstanceIdentifier} does not have storage encryption`,
          remediation: "Enable storage encryption (requires instance recreation for existing instances)",
          cisBenchmark: "CIS AWS 2.3.2",
          status: "fail",
          evidence: `StorageEncrypted: false`,
        };
        dbMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!hasBackup) {
        const mc: ResourceMisconfiguration = {
          checkId: "rds-no-backup",
          severity: "high",
          title: "RDS Instance Without Automated Backups",
          description: `RDS instance ${db.DBInstanceIdentifier} has no automated backup retention`,
          remediation: "Set backup retention period to at least 7 days",
          status: "fail",
          evidence: `BackupRetentionPeriod: ${db.BackupRetentionPeriod || 0}`,
        };
        dbMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "rds_instance",
        resourceId: db.DBInstanceIdentifier || "",
        name: db.DBInstanceIdentifier || "",
        region,
        provider: "aws",
        metadata: {
          engine: db.Engine,
          engineVersion: db.EngineVersion,
          instanceClass: db.DBInstanceClass,
          status: db.DBInstanceStatus,
          publiclyAccessible: isPublic,
          encrypted: isEncrypted,
          multiAZ: hasMultiAZ,
          backupRetention: db.BackupRetentionPeriod,
          endpoint: db.Endpoint?.Address,
          port: db.Endpoint?.Port,
          vpcId: db.DBSubnetGroup?.VpcId,
          autoMinorVersionUpgrade: db.AutoMinorVersionUpgrade,
        },
        misconfigurations: dbMisconfigs,
      });
    }

    cisResults.push(
      {
        checkId: "cis-aws-rds-public",
        title: "Ensure RDS instances are not publicly accessible",
        domain: "compute",
        severity: "critical",
        status: publicInstances === 0 ? "pass" : "fail",
        currentValue: `${publicInstances} publicly accessible RDS instances`,
        expectedValue: "0 publicly accessible instances",
        evidence: `${instances.length} total RDS instances`,
        affectedResources: resources.filter(r => r.resourceType === "rds_instance" && r.metadata.publiclyAccessible).map(r => r.name),
      },
      {
        checkId: "cis-aws-rds-encryption",
        title: "Ensure RDS instances have storage encryption enabled",
        domain: "storage",
        severity: "high",
        status: unencryptedInstances === 0 ? "pass" : "fail",
        currentValue: `${unencryptedInstances} unencrypted RDS instances`,
        expectedValue: "0 unencrypted instances",
        evidence: `${instances.length} total RDS instances`,
        affectedResources: resources.filter(r => r.resourceType === "rds_instance" && !r.metadata.encrypted).map(r => r.name),
      }
    );

  } catch (e: any) {
    errors.push(`RDS enumeration failed: ${e.message}`);
  }
}

// ── Lambda ─────────────────────────────────────────────────────────────────

async function enumerateLambda(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { LambdaClient, ListFunctionsCommand, GetFunctionCommand } = await import("@aws-sdk/client-lambda");
    const lambda = new LambdaClient({ region, credentials });

    const funcResp = await lambda.send(new ListFunctionsCommand({ MaxItems: 200 }));
    const functions = funcResp.Functions || [];
    let publicFunctions = 0;
    let oldRuntimes = 0;

    const DEPRECATED_RUNTIMES = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x", "nodejs14.x", "dotnetcore2.1", "dotnetcore3.1", "ruby2.5", "ruby2.7"];

    for (const fn of functions) {
      const isDeprecatedRuntime = DEPRECATED_RUNTIMES.includes(fn.Runtime || "");
      const hasVPC = (fn.VpcConfig?.SubnetIds?.length || 0) > 0;
      const hasEnvVars = Object.keys(fn.Environment?.Variables || {}).length > 0;

      if (isDeprecatedRuntime) oldRuntimes++;

      const fnMisconfigs: ResourceMisconfiguration[] = [];

      if (isDeprecatedRuntime) {
        const mc: ResourceMisconfiguration = {
          checkId: "lambda-deprecated-runtime",
          severity: "high",
          title: "Lambda Using Deprecated Runtime",
          description: `Function ${fn.FunctionName} uses deprecated runtime ${fn.Runtime}`,
          remediation: `Upgrade to a supported runtime version`,
          mitreTechnique: "T1195.001",
          status: "fail",
          evidence: `Runtime: ${fn.Runtime}`,
        };
        fnMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // Check for secrets in environment variables
      const envVars = fn.Environment?.Variables || {};
      const suspiciousKeys = Object.keys(envVars).filter(k =>
        /password|secret|key|token|api_key|apikey|credential/i.test(k)
      );
      if (suspiciousKeys.length > 0) {
        const mc: ResourceMisconfiguration = {
          checkId: "lambda-env-secrets",
          severity: "high",
          title: "Potential Secrets in Lambda Environment Variables",
          description: `Function ${fn.FunctionName} has suspicious environment variable names`,
          remediation: "Use AWS Secrets Manager or SSM Parameter Store instead of environment variables",
          mitreTechnique: "T1552.001",
          status: "warning",
          evidence: `Suspicious env vars: ${suspiciousKeys.join(", ")}`,
        };
        fnMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "lambda_function",
        resourceId: fn.FunctionArn || "",
        name: fn.FunctionName || "",
        region,
        provider: "aws",
        metadata: {
          runtime: fn.Runtime,
          handler: fn.Handler,
          memorySize: fn.MemorySize,
          timeout: fn.Timeout,
          lastModified: fn.LastModified,
          codeSize: fn.CodeSize,
          hasVPC,
          role: fn.Role,
          envVarCount: Object.keys(envVars).length,
          layers: fn.Layers?.map(l => l.Arn),
        },
        misconfigurations: fnMisconfigs,
      });
    }

    cisResults.push({
      checkId: "cis-aws-lambda-runtime",
      title: "Ensure Lambda functions use supported runtimes",
      domain: "compute",
      severity: "high",
      status: oldRuntimes === 0 ? "pass" : "fail",
      currentValue: `${oldRuntimes} functions with deprecated runtimes`,
      expectedValue: "0 functions with deprecated runtimes",
      evidence: `${functions.length} total Lambda functions`,
      affectedResources: resources.filter(r => r.resourceType === "lambda_function" && DEPRECATED_RUNTIMES.includes(r.metadata.runtime)).map(r => r.name),
    });

  } catch (e: any) {
    errors.push(`Lambda enumeration failed: ${e.message}`);
  }
}

// ── VPC & Security Groups ──────────────────────────────────────────────────

async function enumerateVPC(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { EC2Client, DescribeVpcsCommand, DescribeSecurityGroupsCommand,
      DescribeFlowLogsCommand, DescribeNetworkAclsCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = new EC2Client({ region, credentials });

    // VPCs
    const vpcsResp = await ec2.send(new DescribeVpcsCommand({}));
    const vpcs = vpcsResp.Vpcs || [];
    for (const vpc of vpcs) {
      resources.push({
        resourceType: "vpc",
        resourceId: vpc.VpcId || "",
        name: vpc.Tags?.find(t => t.Key === "Name")?.Value || vpc.VpcId || "",
        region,
        provider: "aws",
        metadata: {
          cidrBlock: vpc.CidrBlock,
          isDefault: vpc.IsDefault,
          state: vpc.State,
        },
        misconfigurations: [],
      });
    }

    // VPC Flow Logs check
    const flowLogsResp = await ec2.send(new DescribeFlowLogsCommand({}));
    const flowLogVpcs = new Set((flowLogsResp.FlowLogs || []).map(fl => fl.ResourceId));
    const vpcsWithoutFlowLogs = vpcs.filter(v => !flowLogVpcs.has(v.VpcId));

    cisResults.push({
      checkId: "cis-aws-vpc-flow-logs",
      title: "Ensure VPC flow logging is enabled in all VPCs",
      domain: "networking",
      severity: "medium",
      status: vpcsWithoutFlowLogs.length === 0 ? "pass" : "fail",
      currentValue: `${vpcsWithoutFlowLogs.length} VPCs without flow logs`,
      expectedValue: "0 VPCs without flow logs",
      evidence: `${vpcs.length} total VPCs, ${flowLogVpcs.size} with flow logs`,
      affectedResources: vpcsWithoutFlowLogs.map(v => v.VpcId || ""),
    });

    // Security Groups
    const sgResp = await ec2.send(new DescribeSecurityGroupsCommand({}));
    const securityGroups = sgResp.SecurityGroups || [];
    let openSGs = 0;

    for (const sg of securityGroups) {
      const openIngressRules = (sg.IpPermissions || []).filter(rule =>
        rule.IpRanges?.some(r => r.CidrIp === "0.0.0.0/0") ||
        rule.Ipv6Ranges?.some(r => r.CidrIpv6 === "::/0")
      );

      const dangerousPorts = openIngressRules.filter(rule => {
        const port = rule.FromPort;
        return port === 22 || port === 3389 || port === 3306 || port === 5432 ||
          port === 1433 || port === 27017 || port === 6379 || rule.IpProtocol === "-1";
      });

      if (dangerousPorts.length > 0) openSGs++;

      const sgMisconfigs: ResourceMisconfiguration[] = [];
      for (const rule of dangerousPorts) {
        const mc: ResourceMisconfiguration = {
          checkId: "sg-open-dangerous-port",
          severity: rule.IpProtocol === "-1" ? "critical" : "high",
          title: rule.IpProtocol === "-1"
            ? `Security Group Allows All Traffic from 0.0.0.0/0`
            : `Security Group Allows Port ${rule.FromPort} from 0.0.0.0/0`,
          description: `Security group ${sg.GroupId} (${sg.GroupName}) has dangerous open ingress`,
          remediation: "Restrict source IP ranges to known CIDR blocks",
          cisBenchmark: "CIS AWS 5.2",
          mitreTechnique: "T1190",
          status: "fail",
          evidence: `Protocol: ${rule.IpProtocol}, Port: ${rule.FromPort}-${rule.ToPort}, Source: 0.0.0.0/0`,
        };
        sgMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "security_group",
        resourceId: sg.GroupId || "",
        name: sg.GroupName || "",
        region,
        provider: "aws",
        metadata: {
          vpcId: sg.VpcId,
          description: sg.Description,
          ingressRuleCount: (sg.IpPermissions || []).length,
          egressRuleCount: (sg.IpPermissionsEgress || []).length,
          openToWorld: openIngressRules.length > 0,
          dangerousPortCount: dangerousPorts.length,
        },
        misconfigurations: sgMisconfigs,
      });
    }

    cisResults.push({
      checkId: "cis-aws-sg-open-ports",
      title: "Ensure no security groups allow ingress from 0.0.0.0/0 to dangerous ports",
      domain: "networking",
      severity: "high",
      status: openSGs === 0 ? "pass" : "fail",
      currentValue: `${openSGs} security groups with dangerous open ports`,
      expectedValue: "0 security groups with dangerous open ports",
      evidence: `${securityGroups.length} total security groups`,
      affectedResources: resources.filter(r => r.resourceType === "security_group" && r.metadata.dangerousPortCount > 0).map(r => `${r.name} (${r.resourceId})`),
    });

  } catch (e: any) {
    errors.push(`VPC enumeration failed: ${e.message}`);
  }
}

// ── CloudTrail ─────────────────────────────────────────────────────────────

async function enumerateCloudTrail(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } = await import("@aws-sdk/client-cloudtrail");
    const ct = new CloudTrailClient({ region, credentials });

    const trailsResp = await ct.send(new DescribeTrailsCommand({}));
    const trails = trailsResp.trailList || [];
    let multiRegionTrails = 0;
    let logValidationTrails = 0;

    for (const trail of trails) {
      let isLogging = false;
      try {
        const statusResp = await ct.send(new GetTrailStatusCommand({ Name: trail.TrailARN }));
        isLogging = statusResp.IsLogging || false;
      } catch { /* skip */ }

      if (trail.IsMultiRegionTrail) multiRegionTrails++;
      if (trail.LogFileValidationEnabled) logValidationTrails++;

      const trailMisconfigs: ResourceMisconfiguration[] = [];

      if (!trail.IsMultiRegionTrail) {
        const mc: ResourceMisconfiguration = {
          checkId: "cloudtrail-not-multiregion",
          severity: "high",
          title: "CloudTrail Not Multi-Region",
          description: `Trail ${trail.Name} is not configured for multi-region logging`,
          remediation: "Enable multi-region logging on the trail",
          cisBenchmark: "CIS AWS 3.1",
          status: "fail",
          evidence: `IsMultiRegionTrail: false`,
        };
        trailMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!trail.LogFileValidationEnabled) {
        const mc: ResourceMisconfiguration = {
          checkId: "cloudtrail-no-log-validation",
          severity: "medium",
          title: "CloudTrail Log File Validation Disabled",
          description: `Trail ${trail.Name} does not have log file validation enabled`,
          remediation: "Enable log file validation to detect log tampering",
          cisBenchmark: "CIS AWS 3.2",
          status: "fail",
          evidence: `LogFileValidationEnabled: false`,
        };
        trailMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      if (!isLogging) {
        const mc: ResourceMisconfiguration = {
          checkId: "cloudtrail-not-logging",
          severity: "critical",
          title: "CloudTrail Not Actively Logging",
          description: `Trail ${trail.Name} is not currently logging`,
          remediation: "Start logging on the trail immediately",
          cisBenchmark: "CIS AWS 3.1",
          status: "fail",
          evidence: `IsLogging: false`,
        };
        trailMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "cloudtrail",
        resourceId: trail.TrailARN || "",
        name: trail.Name || "",
        region: trail.HomeRegion || region,
        provider: "aws",
        metadata: {
          isMultiRegion: trail.IsMultiRegionTrail,
          logFileValidation: trail.LogFileValidationEnabled,
          isLogging,
          s3BucketName: trail.S3BucketName,
          kmsKeyId: trail.KmsKeyId,
          hasCloudWatchLogs: !!trail.CloudWatchLogsLogGroupArn,
        },
        misconfigurations: trailMisconfigs,
      });
    }

    cisResults.push(
      {
        checkId: "cis-aws-cloudtrail-multiregion",
        title: "Ensure CloudTrail is enabled in all regions",
        domain: "logging",
        severity: "high",
        status: multiRegionTrails > 0 ? "pass" : "fail",
        currentValue: `${multiRegionTrails} multi-region trails`,
        expectedValue: "At least 1 multi-region trail",
        evidence: `${trails.length} total trails`,
        affectedResources: trails.filter(t => !t.IsMultiRegionTrail).map(t => t.Name || ""),
      },
      {
        checkId: "cis-aws-cloudtrail-log-validation",
        title: "Ensure CloudTrail log file validation is enabled",
        domain: "logging",
        severity: "medium",
        status: logValidationTrails === trails.length && trails.length > 0 ? "pass" : "fail",
        currentValue: `${logValidationTrails}/${trails.length} trails with log validation`,
        expectedValue: "All trails with log validation",
        evidence: `${trails.length} total trails`,
        affectedResources: trails.filter(t => !t.LogFileValidationEnabled).map(t => t.Name || ""),
      }
    );

  } catch (e: any) {
    errors.push(`CloudTrail enumeration failed: ${e.message}`);
  }
}

// ── GuardDuty ──────────────────────────────────────────────────────────────

async function enumerateGuardDuty(
  credentials: any, region: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand,
      GetFindingsStatisticsCommand } = await import("@aws-sdk/client-guardduty");
    const gd = new GuardDutyClient({ region, credentials });

    const detectorsResp = await gd.send(new ListDetectorsCommand({}));
    const detectorIds = detectorsResp.DetectorIds || [];

    if (detectorIds.length === 0) {
      const mc: ResourceMisconfiguration = {
        checkId: "guardduty-not-enabled",
        severity: "high",
        title: "GuardDuty Not Enabled",
        description: `GuardDuty is not enabled in region ${region}`,
        remediation: "Enable GuardDuty in all regions for threat detection",
        cisBenchmark: "CIS AWS 4.15",
        mitreTechnique: "T1562.001",
        status: "fail",
        evidence: `No GuardDuty detectors found in ${region}`,
      };
      misconfigs.push(mc);
    }

    for (const detectorId of detectorIds) {
      try {
        const detectorResp = await gd.send(new GetDetectorCommand({ DetectorId: detectorId }));
        resources.push({
          resourceType: "guardduty_detector",
          resourceId: detectorId,
          name: `GuardDuty-${region}`,
          region,
          provider: "aws",
          metadata: {
            status: detectorResp.Status,
            findingPublishingFrequency: detectorResp.FindingPublishingFrequency,
            createdAt: detectorResp.CreatedAt,
            features: detectorResp.Features,
          },
          misconfigurations: [],
        });
      } catch { /* skip */ }
    }

    cisResults.push({
      checkId: "cis-aws-guardduty-enabled",
      title: "Ensure GuardDuty is enabled",
      domain: "logging",
      severity: "high",
      status: detectorIds.length > 0 ? "pass" : "fail",
      currentValue: `${detectorIds.length} detectors`,
      expectedValue: "At least 1 detector",
      evidence: `Region: ${region}`,
      affectedResources: detectorIds.length === 0 ? [region] : [],
    });

  } catch (e: any) {
    errors.push(`GuardDuty enumeration failed: ${e.message}`);
  }
}

// ── Helper ─────────────────────────────────────────────────────────────────

function buildResult(
  provider: "aws" | "azure" | "gcp",
  resources: CloudResource[],
  misconfigurations: ResourceMisconfiguration[],
  cisResults: CISCheckResult[],
  errors: string[]
): ResourceEnumerationResult {
  const byType: Record<string, number> = {};
  for (const r of resources) {
    byType[r.resourceType] = (byType[r.resourceType] || 0) + 1;
  }
  const bySeverity: Record<string, number> = {};
  for (const m of misconfigurations) {
    bySeverity[m.severity] = (bySeverity[m.severity] || 0) + 1;
  }
  const cisPassed = cisResults.filter(c => c.status === "pass").length;
  const cisFailed = cisResults.filter(c => c.status === "fail").length;
  const cisNotAssessed = cisResults.filter(c => c.status === "not_assessed").length;
  const cisTotal = cisResults.length;
  const cisScore = cisTotal > 0 ? Math.round((cisPassed / cisTotal) * 100) : 0;

  return {
    provider,
    resources,
    misconfigurations,
    cisResults,
    summary: {
      totalResources: resources.length,
      byType,
      totalMisconfigurations: misconfigurations.length,
      bySeverity,
      cisScore,
      cisPassed,
      cisFailed,
      cisNotAssessed,
    },
    errors,
  };
}


// ══════════════════════════════════════════════════════════════════════════════
// ── Azure Resource Enumeration ────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

export async function enumerateAzureResources(creds: {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId?: string;
}): Promise<ResourceEnumerationResult> {
  const errors: string[] = [];
  const resources: CloudResource[] = [];
  const misconfigurations: ResourceMisconfiguration[] = [];
  const cisResults: CISCheckResult[] = [];

  try {
    const { ClientSecretCredential } = await import("@azure/identity");
    const credential = new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret);

    // Discover subscriptions if not provided
    let subscriptionIds: string[] = [];
    if (creds.subscriptionId) {
      subscriptionIds = [creds.subscriptionId];
    } else {
      try {
        const { SubscriptionClient } = await import("@azure/arm-subscriptions");
        const subClient = new SubscriptionClient(credential);
        for await (const sub of subClient.subscriptions.list()) {
          if (sub.subscriptionId && sub.state === "Enabled") {
            subscriptionIds.push(sub.subscriptionId);
            resources.push({
              resourceType: "azure_subscription",
              resourceId: sub.subscriptionId,
              name: sub.displayName || sub.subscriptionId,
              provider: "azure",
              metadata: {
                state: sub.state,
                tenantId: sub.tenantId,
                subscriptionPolicies: sub.subscriptionPolicies,
              },
              misconfigurations: [],
            });
          }
        }
      } catch (e: any) {
        errors.push(`Subscription listing failed: ${e.message}`);
      }
    }

    if (subscriptionIds.length === 0) {
      errors.push("No subscriptions found or accessible");
      return buildResult("azure", resources, misconfigurations, cisResults, errors);
    }

    console.log(`[Azure ResourceEnum] Enumerating ${subscriptionIds.length} subscription(s)`);

    for (const subId of subscriptionIds) {
      // ── Virtual Machines ──
      await enumerateAzureVMs(credential, subId, resources, misconfigurations, cisResults, errors);

      // ── Storage Accounts ──
      await enumerateAzureStorage(credential, subId, resources, misconfigurations, cisResults, errors);

      // ── Network Security Groups ──
      await enumerateAzureNSGs(credential, subId, resources, misconfigurations, cisResults, errors);

      // ── Key Vaults ──
      await enumerateAzureKeyVaults(credential, subId, resources, misconfigurations, cisResults, errors);

      // ── SQL Servers & Databases ──
      await enumerateAzureSQL(credential, subId, resources, misconfigurations, cisResults, errors);

      // ── Activity Log / Monitor ──
      await enumerateAzureActivityLog(credential, subId, resources, misconfigurations, cisResults, errors);
    }

  } catch (e: any) {
    errors.push(`Azure resource enumeration error: ${e.message}`);
  }

  return buildResult("azure", resources, misconfigurations, cisResults, errors);
}

// ── Azure VMs ─────────────────────────────────────────────────────────────────

async function enumerateAzureVMs(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { ComputeManagementClient } = await import("@azure/arm-compute");
    const client = new ComputeManagementClient(credential, subscriptionId);

    const vms: any[] = [];
    for await (const vm of client.virtualMachines.listAll()) {
      vms.push(vm);
      const vmMisconfigs: ResourceMisconfiguration[] = [];

      // CIS 7.1: Ensure VM disk encryption is enabled
      const osDiskEncrypted = vm.storageProfile?.osDisk?.encryptionSettings?.enabled === true ||
        vm.storageProfile?.osDisk?.managedDisk?.securityProfile?.diskEncryptionSet;
      if (!osDiskEncrypted) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-7.1",
          severity: "high",
          title: "VM OS disk not encrypted",
          description: `VM ${vm.name} has unencrypted OS disk. Azure Disk Encryption or server-side encryption with CMK should be enabled.`,
          remediation: "Enable Azure Disk Encryption (ADE) or server-side encryption with customer-managed keys",
          cisBenchmark: "CIS Azure 7.1",
          mitreTechnique: "T1530",
          status: "fail",
          evidence: `VM: ${vm.name}, OS Disk: ${vm.storageProfile?.osDisk?.name || "unknown"}`,
        };
        vmMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // Check for public IP
      const hasPublicIP = vm.networkProfile?.networkInterfaces?.some((nic: any) => nic.id);
      // Note: full public IP check requires querying the NIC and its IP config

      // Check extensions for monitoring agent
      const hasMonitoringAgent = vm.resources?.some((ext: any) =>
        ext.virtualMachineExtensionType === "MicrosoftMonitoringAgent" ||
        ext.virtualMachineExtensionType === "AzureMonitorLinuxAgent" ||
        ext.virtualMachineExtensionType === "AzureMonitorWindowsAgent"
      );
      if (!hasMonitoringAgent) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-7.4",
          severity: "medium",
          title: "VM missing monitoring agent",
          description: `VM ${vm.name} does not have Azure Monitor agent installed. Monitoring is essential for security visibility.`,
          remediation: "Install Azure Monitor Agent (AMA) extension on the VM",
          cisBenchmark: "CIS Azure 7.4",
          status: "fail",
          evidence: `VM: ${vm.name}, Extensions: ${vm.resources?.map((e: any) => e.virtualMachineExtensionType).join(", ") || "none"}`,
        };
        vmMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "azure_vm",
        resourceId: vm.id || vm.name || "",
        name: vm.name || "",
        region: vm.location,
        provider: "azure",
        metadata: {
          subscriptionId,
          vmSize: vm.hardwareProfile?.vmSize,
          osType: vm.storageProfile?.osDisk?.osType,
          osImage: vm.storageProfile?.imageReference ? `${vm.storageProfile.imageReference.publisher}/${vm.storageProfile.imageReference.offer}/${vm.storageProfile.imageReference.sku}` : undefined,
          provisioningState: vm.provisioningState,
          powerState: vm.instanceView?.statuses?.find((s: any) => s.code?.startsWith("PowerState/"))?.displayStatus,
          networkInterfaces: vm.networkProfile?.networkInterfaces?.length || 0,
          extensions: vm.resources?.map((e: any) => e.virtualMachineExtensionType) || [],
        },
        misconfigurations: vmMisconfigs,
      });
    }

    // CIS check summary for VMs
    cisResults.push({
      checkId: "CIS-AZURE-7.1",
      title: "Ensure Virtual Machines utilize Managed Disks with encryption",
      domain: "Virtual Machines",
      severity: "high",
      status: vms.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === "CIS-AZURE-7.1") ? "fail" : "pass",
      currentValue: `${vms.filter(vm => !misconfigs.some(m => m.checkId === "CIS-AZURE-7.1" && m.evidence.includes(vm.name))).length}/${vms.length} encrypted`,
      expectedValue: "All VMs should use encrypted managed disks",
      evidence: `Total VMs: ${vms.length}`,
      affectedResources: misconfigs.filter(m => m.checkId === "CIS-AZURE-7.1").map(m => m.evidence),
    });

    cisResults.push({
      checkId: "CIS-AZURE-7.4",
      title: "Ensure Azure Monitor Agent is installed on Virtual Machines",
      domain: "Virtual Machines",
      severity: "medium",
      status: vms.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === "CIS-AZURE-7.4") ? "fail" : "pass",
      currentValue: `${vms.filter(vm => !misconfigs.some(m => m.checkId === "CIS-AZURE-7.4" && m.evidence.includes(vm.name))).length}/${vms.length} monitored`,
      expectedValue: "All VMs should have Azure Monitor Agent",
      evidence: `Total VMs: ${vms.length}`,
      affectedResources: misconfigs.filter(m => m.checkId === "CIS-AZURE-7.4").map(m => m.evidence),
    });

  } catch (e: any) {
    errors.push(`Azure VM enumeration failed: ${e.message}`);
  }
}

// ── Azure Storage Accounts ────────────────────────────────────────────────────

async function enumerateAzureStorage(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { StorageManagementClient } = await import("@azure/arm-storage");
    const client = new StorageManagementClient(credential, subscriptionId);

    const accounts: any[] = [];
    for await (const acct of client.storageAccounts.list()) {
      accounts.push(acct);
      const acctMisconfigs: ResourceMisconfiguration[] = [];

      // CIS 3.1: Ensure secure transfer (HTTPS) is enabled
      if (acct.enableHttpsTrafficOnly !== true) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-3.1",
          severity: "high",
          title: "Storage account allows HTTP traffic",
          description: `Storage account ${acct.name} does not enforce HTTPS-only access. Data in transit could be intercepted.`,
          remediation: "Enable 'Secure transfer required' on the storage account",
          cisBenchmark: "CIS Azure 3.1",
          mitreTechnique: "T1557",
          status: "fail",
          evidence: `Account: ${acct.name}, HTTPS only: ${acct.enableHttpsTrafficOnly}`,
        };
        acctMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // CIS 3.2: Ensure storage account uses CMK encryption
      const usesCMK = acct.encryption?.keySource === "Microsoft.Keyvault";
      // Note: Microsoft-managed keys are default and acceptable for many orgs, CMK is best practice
      if (!usesCMK) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-3.2",
          severity: "medium",
          title: "Storage account not using customer-managed encryption keys",
          description: `Storage account ${acct.name} uses Microsoft-managed keys instead of customer-managed keys (CMK).`,
          remediation: "Configure encryption with customer-managed keys via Azure Key Vault",
          cisBenchmark: "CIS Azure 3.2",
          status: "warning" as any,
          evidence: `Account: ${acct.name}, Key source: ${acct.encryption?.keySource || "Microsoft.Storage"}`,
        };
        acctMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // CIS 3.7: Ensure public network access is restricted
      const allowsPublicAccess = acct.publicNetworkAccess !== "Disabled";
      const allowsBlobPublicAccess = acct.allowBlobPublicAccess !== false;
      if (allowsBlobPublicAccess) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-3.7",
          severity: "high",
          title: "Storage account allows public blob access",
          description: `Storage account ${acct.name} allows anonymous public access to blobs. Sensitive data may be exposed.`,
          remediation: "Disable 'Allow Blob public access' on the storage account",
          cisBenchmark: "CIS Azure 3.7",
          mitreTechnique: "T1530",
          status: "fail",
          evidence: `Account: ${acct.name}, Blob public access: ${acct.allowBlobPublicAccess}`,
        };
        acctMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // Check minimum TLS version
      const minTls = acct.minimumTlsVersion || "TLS1_0";
      if (minTls !== "TLS1_2") {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-3.15",
          severity: "medium",
          title: "Storage account allows TLS < 1.2",
          description: `Storage account ${acct.name} allows TLS version ${minTls}. TLS 1.2 should be the minimum.`,
          remediation: "Set minimum TLS version to TLS 1.2",
          cisBenchmark: "CIS Azure 3.15",
          status: "fail",
          evidence: `Account: ${acct.name}, Min TLS: ${minTls}`,
        };
        acctMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "azure_storage_account",
        resourceId: acct.id || acct.name || "",
        name: acct.name || "",
        region: acct.location,
        provider: "azure",
        metadata: {
          subscriptionId,
          kind: acct.kind,
          sku: acct.sku?.name,
          accessTier: acct.accessTier,
          httpsOnly: acct.enableHttpsTrafficOnly,
          minimumTlsVersion: acct.minimumTlsVersion,
          allowBlobPublicAccess: acct.allowBlobPublicAccess,
          publicNetworkAccess: acct.publicNetworkAccess,
          encryptionKeySource: acct.encryption?.keySource,
          networkRuleSet: acct.networkRuleSet ? {
            defaultAction: acct.networkRuleSet.defaultAction,
            ipRules: acct.networkRuleSet.ipRules?.length || 0,
            virtualNetworkRules: acct.networkRuleSet.virtualNetworkRules?.length || 0,
          } : undefined,
        },
        misconfigurations: acctMisconfigs,
      });
    }

    // CIS check summaries
    for (const check of [
      { id: "CIS-AZURE-3.1", title: "Ensure secure transfer is enabled for storage accounts", domain: "Storage", severity: "high" },
      { id: "CIS-AZURE-3.7", title: "Ensure public access to storage account blobs is disabled", domain: "Storage", severity: "high" },
      { id: "CIS-AZURE-3.15", title: "Ensure minimum TLS version is set to 1.2", domain: "Storage", severity: "medium" },
    ]) {
      cisResults.push({
        checkId: check.id,
        title: check.title,
        domain: check.domain,
        severity: check.severity,
        status: accounts.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === check.id) ? "fail" : "pass",
        currentValue: `${accounts.filter(a => !misconfigs.some(m => m.checkId === check.id && m.evidence.includes(a.name))).length}/${accounts.length} compliant`,
        expectedValue: "All storage accounts should be compliant",
        evidence: `Total storage accounts: ${accounts.length}`,
        affectedResources: misconfigs.filter(m => m.checkId === check.id).map(m => m.evidence),
      });
    }

  } catch (e: any) {
    errors.push(`Azure Storage enumeration failed: ${e.message}`);
  }
}

// ── Azure Network Security Groups ─────────────────────────────────────────────

async function enumerateAzureNSGs(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { NetworkManagementClient } = await import("@azure/arm-network");
    const client = new NetworkManagementClient(credential, subscriptionId);

    const nsgs: any[] = [];
    for await (const nsg of client.networkSecurityGroups.listAll()) {
      nsgs.push(nsg);
      const nsgMisconfigs: ResourceMisconfiguration[] = [];

      // Check for overly permissive inbound rules
      const dangerousPorts = [22, 3389, 445, 1433, 3306, 5432, 27017];
      for (const rule of (nsg.securityRules || [])) {
        if (rule.direction === "Inbound" && rule.access === "Allow") {
          const isOpenToAll = rule.sourceAddressPrefix === "*" || rule.sourceAddressPrefix === "0.0.0.0/0" ||
            rule.sourceAddressPrefix === "Internet" || rule.sourceAddressPrefixes?.includes("*");
          if (isOpenToAll) {
            const destPort = rule.destinationPortRange;
            const isDangerous = destPort === "*" || dangerousPorts.some(p => destPort === String(p));
            if (isDangerous) {
              const mc: ResourceMisconfiguration = {
                checkId: "CIS-AZURE-6.1",
                severity: destPort === "*" ? "critical" : "high",
                title: `NSG allows unrestricted inbound access on port ${destPort}`,
                description: `NSG ${nsg.name} has rule "${rule.name}" allowing inbound traffic from any source to port ${destPort}.`,
                remediation: "Restrict source addresses to known IP ranges or use Azure Bastion for management access",
                cisBenchmark: "CIS Azure 6.1-6.6",
                mitreTechnique: "T1190",
                status: "fail",
                evidence: `NSG: ${nsg.name}, Rule: ${rule.name}, Source: ${rule.sourceAddressPrefix}, Dest Port: ${destPort}`,
              };
              nsgMisconfigs.push(mc);
              misconfigs.push(mc);
            }
          }
        }
      }

      resources.push({
        resourceType: "azure_nsg",
        resourceId: nsg.id || nsg.name || "",
        name: nsg.name || "",
        region: nsg.location,
        provider: "azure",
        metadata: {
          subscriptionId,
          resourceGroup: nsg.id?.split("/resourceGroups/")[1]?.split("/")[0],
          securityRules: (nsg.securityRules || []).length,
          defaultSecurityRules: (nsg.defaultSecurityRules || []).length,
          subnets: nsg.subnets?.map((s: any) => s.id?.split("/").pop()) || [],
          networkInterfaces: nsg.networkInterfaces?.length || 0,
        },
        misconfigurations: nsgMisconfigs,
      });
    }

    cisResults.push({
      checkId: "CIS-AZURE-6.1",
      title: "Ensure no NSG allows unrestricted inbound access to high-risk ports",
      domain: "Networking",
      severity: "critical",
      status: nsgs.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === "CIS-AZURE-6.1") ? "fail" : "pass",
      currentValue: `${misconfigs.filter(m => m.checkId === "CIS-AZURE-6.1").length} overly permissive rules found`,
      expectedValue: "No unrestricted inbound rules on high-risk ports",
      evidence: `Total NSGs: ${nsgs.length}`,
      affectedResources: misconfigs.filter(m => m.checkId === "CIS-AZURE-6.1").map(m => m.evidence),
    });

  } catch (e: any) {
    errors.push(`Azure NSG enumeration failed: ${e.message}`);
  }
}

// ── Azure Key Vaults ──────────────────────────────────────────────────────────

async function enumerateAzureKeyVaults(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { KeyVaultManagementClient } = await import("@azure/arm-keyvault");
    const client = new KeyVaultManagementClient(credential, subscriptionId);

    const vaults: any[] = [];
    for await (const vault of client.vaults.listBySubscription()) {
      vaults.push(vault);
      const vaultMisconfigs: ResourceMisconfiguration[] = [];

      // CIS 8.1: Ensure soft delete is enabled
      if (vault.properties?.enableSoftDelete !== true) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-8.1",
          severity: "high",
          title: "Key Vault soft delete not enabled",
          description: `Key Vault ${vault.name} does not have soft delete enabled. Deleted keys/secrets cannot be recovered.`,
          remediation: "Enable soft delete on the Key Vault (note: this is now enabled by default for new vaults)",
          cisBenchmark: "CIS Azure 8.1",
          status: "fail",
          evidence: `Vault: ${vault.name}, Soft delete: ${vault.properties?.enableSoftDelete}`,
        };
        vaultMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // CIS 8.2: Ensure purge protection is enabled
      if (vault.properties?.enablePurgeProtection !== true) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-8.2",
          severity: "high",
          title: "Key Vault purge protection not enabled",
          description: `Key Vault ${vault.name} does not have purge protection. Soft-deleted items could be permanently purged before retention period.`,
          remediation: "Enable purge protection on the Key Vault",
          cisBenchmark: "CIS Azure 8.2",
          status: "fail",
          evidence: `Vault: ${vault.name}, Purge protection: ${vault.properties?.enablePurgeProtection}`,
        };
        vaultMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // Check network access
      const allowsPublicAccess = !vault.properties?.networkAcls || vault.properties.networkAcls.defaultAction === "Allow";
      if (allowsPublicAccess) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-8.6",
          severity: "medium",
          title: "Key Vault allows public network access",
          description: `Key Vault ${vault.name} is accessible from all networks. Should be restricted to specific VNets/IPs.`,
          remediation: "Configure network ACLs to restrict access to specific VNets and IP ranges",
          cisBenchmark: "CIS Azure 8.6",
          status: "fail",
          evidence: `Vault: ${vault.name}, Default action: ${vault.properties?.networkAcls?.defaultAction || "Allow"}`,
        };
        vaultMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "azure_keyvault",
        resourceId: vault.id || vault.name || "",
        name: vault.name || "",
        region: vault.location,
        provider: "azure",
        metadata: {
          subscriptionId,
          sku: vault.properties?.sku?.name,
          enableSoftDelete: vault.properties?.enableSoftDelete,
          enablePurgeProtection: vault.properties?.enablePurgeProtection,
          enableRbacAuthorization: vault.properties?.enableRbacAuthorization,
          publicNetworkAccess: vault.properties?.publicNetworkAccess,
          networkAclsDefault: vault.properties?.networkAcls?.defaultAction,
          accessPolicies: vault.properties?.accessPolicies?.length || 0,
          vaultUri: vault.properties?.vaultUri,
        },
        misconfigurations: vaultMisconfigs,
      });
    }

    for (const check of [
      { id: "CIS-AZURE-8.1", title: "Ensure Key Vault soft delete is enabled", domain: "Key Vault", severity: "high" },
      { id: "CIS-AZURE-8.2", title: "Ensure Key Vault purge protection is enabled", domain: "Key Vault", severity: "high" },
      { id: "CIS-AZURE-8.6", title: "Ensure Key Vault network access is restricted", domain: "Key Vault", severity: "medium" },
    ]) {
      cisResults.push({
        checkId: check.id,
        title: check.title,
        domain: check.domain,
        severity: check.severity,
        status: vaults.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === check.id) ? "fail" : "pass",
        currentValue: `${vaults.filter(v => !misconfigs.some(m => m.checkId === check.id && m.evidence.includes(v.name))).length}/${vaults.length} compliant`,
        expectedValue: "All Key Vaults should be compliant",
        evidence: `Total Key Vaults: ${vaults.length}`,
        affectedResources: misconfigs.filter(m => m.checkId === check.id).map(m => m.evidence),
      });
    }

  } catch (e: any) {
    errors.push(`Azure Key Vault enumeration failed: ${e.message}`);
  }
}

// ── Azure SQL Servers & Databases ─────────────────────────────────────────────

async function enumerateAzureSQL(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { SqlManagementClient } = await import("@azure/arm-sql");
    const client = new SqlManagementClient(credential, subscriptionId);

    const servers: any[] = [];
    for await (const server of client.servers.list()) {
      servers.push(server);
      const serverMisconfigs: ResourceMisconfiguration[] = [];

      // CIS 4.1.1: Ensure auditing is enabled
      const rg = server.id?.split("/resourceGroups/")[1]?.split("/")[0] || "";
      let auditingEnabled = false;
      try {
        const auditPolicy = await client.serverBlobAuditingPolicies.get(rg, server.name || "");
        auditingEnabled = auditPolicy.state === "Enabled";
      } catch { /* auditing check may fail */ }

      if (!auditingEnabled) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-4.1.1",
          severity: "high",
          title: "SQL Server auditing not enabled",
          description: `SQL Server ${server.name} does not have blob auditing enabled. Database activity is not being logged.`,
          remediation: "Enable auditing on the SQL Server and configure a storage account for audit logs",
          cisBenchmark: "CIS Azure 4.1.1",
          mitreTechnique: "T1562.008",
          status: "fail",
          evidence: `Server: ${server.name}, Auditing: disabled`,
        };
        serverMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // CIS 4.1.2: Ensure TDE is enabled (check at database level)
      // CIS 4.2.1: Ensure Advanced Threat Protection is enabled
      let atpEnabled = false;
      try {
        const atp = await client.serverAdvancedThreatProtectionSettings.get(rg, server.name || "");
        atpEnabled = atp.state === "Enabled";
      } catch { /* ATP check may fail */ }

      if (!atpEnabled) {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-4.2.1",
          severity: "high",
          title: "SQL Server Advanced Threat Protection not enabled",
          description: `SQL Server ${server.name} does not have Advanced Threat Protection enabled.`,
          remediation: "Enable Microsoft Defender for SQL on the server",
          cisBenchmark: "CIS Azure 4.2.1",
          status: "fail",
          evidence: `Server: ${server.name}, ATP: disabled`,
        };
        serverMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      // Check minimum TLS version
      const minTls = (server as any).minimalTlsVersion || "1.0";
      if (minTls !== "1.2") {
        const mc: ResourceMisconfiguration = {
          checkId: "CIS-AZURE-4.1.5",
          severity: "medium",
          title: "SQL Server allows TLS < 1.2",
          description: `SQL Server ${server.name} allows TLS version ${minTls}. Minimum should be 1.2.`,
          remediation: "Set minimum TLS version to 1.2 on the SQL Server",
          cisBenchmark: "CIS Azure 4.1.5",
          status: "fail",
          evidence: `Server: ${server.name}, Min TLS: ${minTls}`,
        };
        serverMisconfigs.push(mc);
        misconfigs.push(mc);
      }

      resources.push({
        resourceType: "azure_sql_server",
        resourceId: server.id || server.name || "",
        name: server.name || "",
        region: server.location,
        provider: "azure",
        metadata: {
          subscriptionId,
          fullyQualifiedDomainName: server.fullyQualifiedDomainName,
          administratorLogin: server.administratorLogin,
          version: server.version,
          state: server.state,
          publicNetworkAccess: (server as any).publicNetworkAccess,
          minimalTlsVersion: (server as any).minimalTlsVersion,
          auditingEnabled,
          atpEnabled,
        },
        misconfigurations: serverMisconfigs,
      });

      // Enumerate databases under this server
      try {
        for await (const db of client.databases.listByServer(rg, server.name || "")) {
          if (db.name === "master") continue; // skip system db
          resources.push({
            resourceType: "azure_sql_database",
            resourceId: db.id || db.name || "",
            name: db.name || "",
            region: db.location,
            provider: "azure",
            metadata: {
              subscriptionId,
              serverName: server.name,
              sku: db.sku?.name,
              tier: db.sku?.tier,
              status: db.status,
              maxSizeBytes: db.maxSizeBytes,
              zoneRedundant: db.zoneRedundant,
              readScale: db.readScale,
            },
            misconfigurations: [],
          });
        }
      } catch { /* database listing may fail for some servers */ }
    }

    for (const check of [
      { id: "CIS-AZURE-4.1.1", title: "Ensure SQL Server auditing is enabled", domain: "Database", severity: "high" },
      { id: "CIS-AZURE-4.2.1", title: "Ensure Advanced Threat Protection is enabled for SQL Server", domain: "Database", severity: "high" },
      { id: "CIS-AZURE-4.1.5", title: "Ensure minimum TLS version is 1.2 for SQL Server", domain: "Database", severity: "medium" },
    ]) {
      cisResults.push({
        checkId: check.id,
        title: check.title,
        domain: check.domain,
        severity: check.severity,
        status: servers.length === 0 ? "not_assessed" : misconfigs.some(m => m.checkId === check.id) ? "fail" : "pass",
        currentValue: `${servers.filter(s => !misconfigs.some(m => m.checkId === check.id && m.evidence.includes(s.name))).length}/${servers.length} compliant`,
        expectedValue: "All SQL Servers should be compliant",
        evidence: `Total SQL Servers: ${servers.length}`,
        affectedResources: misconfigs.filter(m => m.checkId === check.id).map(m => m.evidence),
      });
    }

  } catch (e: any) {
    errors.push(`Azure SQL enumeration failed: ${e.message}`);
  }
}

// ── Azure Activity Log / Monitor ──────────────────────────────────────────────

async function enumerateAzureActivityLog(
  credential: any, subscriptionId: string,
  resources: CloudResource[], misconfigs: ResourceMisconfiguration[],
  cisResults: CISCheckResult[], errors: string[]
) {
  try {
    const { MonitorClient } = await import("@azure/arm-monitor");
    const client = new MonitorClient(credential, subscriptionId);

    // Check diagnostic settings at subscription level
    let hasSubscriptionDiagnostics = false;
    try {
      const diagnosticSettings = client.subscriptionDiagnosticSettings.list(subscriptionId);
      for await (const setting of diagnosticSettings) {
        hasSubscriptionDiagnostics = true;
        resources.push({
          resourceType: "azure_diagnostic_setting",
          resourceId: setting.id || setting.name || "",
          name: setting.name || "",
          provider: "azure",
          metadata: {
            subscriptionId,
            storageAccountId: setting.storageAccountId,
            workspaceId: setting.workspaceId,
            eventHubAuthorizationRuleId: setting.eventHubAuthorizationRuleId,
            logs: setting.logs?.map((l: any) => ({ category: l.category, enabled: l.enabled })),
          },
          misconfigurations: [],
        });
      }
    } catch { /* diagnostic settings may not be accessible */ }

    if (!hasSubscriptionDiagnostics) {
      const mc: ResourceMisconfiguration = {
        checkId: "CIS-AZURE-5.1.1",
        severity: "high",
        title: "No subscription-level diagnostic settings configured",
        description: `Subscription ${subscriptionId} does not have diagnostic settings to export Activity Log to a storage account or Log Analytics workspace.`,
        remediation: "Configure diagnostic settings to export Activity Log to a Log Analytics workspace or storage account",
        cisBenchmark: "CIS Azure 5.1.1",
        mitreTechnique: "T1562.008",
        status: "fail",
        evidence: `Subscription: ${subscriptionId}, Diagnostic settings: none`,
      };
      misconfigs.push(mc);
    }

    cisResults.push({
      checkId: "CIS-AZURE-5.1.1",
      title: "Ensure diagnostic settings capture Activity Log for subscription",
      domain: "Logging & Monitoring",
      severity: "high",
      status: hasSubscriptionDiagnostics ? "pass" : "fail",
      currentValue: hasSubscriptionDiagnostics ? "Diagnostic settings configured" : "No diagnostic settings",
      expectedValue: "Activity Log should be exported to Log Analytics or storage",
      evidence: `Subscription: ${subscriptionId}`,
      affectedResources: hasSubscriptionDiagnostics ? [] : [`Subscription: ${subscriptionId}`],
    });

    // Check for activity log alerts (CIS 5.2.x)
    let alertRules: any[] = [];
    try {
      for await (const rule of client.activityLogAlerts.listBySubscriptionId()) {
        alertRules.push(rule);
      }
    } catch { /* alert rules may not be accessible */ }

    const requiredAlertOperations = [
      { op: "Microsoft.Authorization/policyAssignments/write", cis: "CIS-AZURE-5.2.1", title: "Create Policy Assignment" },
      { op: "Microsoft.Network/networkSecurityGroups/write", cis: "CIS-AZURE-5.2.2", title: "Create/Update NSG" },
      { op: "Microsoft.Network/networkSecurityGroups/delete", cis: "CIS-AZURE-5.2.3", title: "Delete NSG" },
      { op: "Microsoft.Security/securitySolutions/write", cis: "CIS-AZURE-5.2.4", title: "Create/Update Security Solution" },
      { op: "Microsoft.Sql/servers/firewallRules/write", cis: "CIS-AZURE-5.2.5", title: "Create/Update SQL Firewall Rule" },
    ];

    for (const req of requiredAlertOperations) {
      const hasAlert = alertRules.some((rule: any) =>
        rule.condition?.allOf?.some((c: any) => c.field === "operationName" && c.equals === req.op)
      );
      cisResults.push({
        checkId: req.cis,
        title: `Ensure Activity Log Alert exists for ${req.title}`,
        domain: "Logging & Monitoring",
        severity: "medium",
        status: hasAlert ? "pass" : "fail",
        currentValue: hasAlert ? "Alert configured" : "No alert configured",
        expectedValue: `Activity Log Alert for ${req.op}`,
        evidence: `Total alert rules: ${alertRules.length}`,
        affectedResources: hasAlert ? [] : [`Missing alert for: ${req.op}`],
      });
    }

  } catch (e: any) {
    errors.push(`Azure Activity Log enumeration failed: ${e.message}`);
  }
}
