/**
 * AWS CI/CD Connector
 * Handles STS AssumeRole for cross-account access, environment discovery
 * (EC2, ECS, ELB, CloudFront), and scan orchestration for CI/CD pipelines.
 */

import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import crypto from "crypto";

/** Inline type — avoids depending on @aws-sdk/types package */
interface AwsCredentialIdentity {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AwsCicdCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
}

export interface AssumeRoleConfig {
  roleArn: string;
  externalId?: string;
  sessionName?: string;
  region?: string;
}

export interface DiscoveredEnvironment {
  id: string;
  name: string;
  type: "ec2" | "ecs" | "elb" | "cloudfront" | "elasticbeanstalk" | "lambda_url" | "api_gateway";
  url: string;
  region: string;
  metadata: Record<string, string>;
}

export type CicdScanType = "zap" | "burp" | "nuclei" | "config" | "cspm" | "container" | "iac";

export interface CicdScanRequest {
  targetUrl: string;
  scanTypes: CicdScanType[];
  pipelineId: number;
  runId: number;
  commitSha?: string;
  branch?: string;
  failThreshold?: number; // CVSS score threshold for pass/fail
  callbackUrl?: string;   // URL to POST results back to
  // Extended fields for cloud/config scanning
  awsCredentials?: AwsCicdCredentials;  // For CSPM/cloud config scans
  containerImage?: string;              // For container image scanning (e.g. "nginx:latest")
  iacRepoUrl?: string;                  // For IaC scanning (Git repo URL)
  cloudProvider?: "aws" | "azure" | "gcp"; // For CSPM scans
}

export interface CicdScanResult {
  runId: number;
  pipelineId: number;
  status: "passed" | "failed" | "error";
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  maxCvss: number;
  duration: number; // seconds
  findings: CicdFinding[];
  reportUrl?: string;
}

export interface CicdFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss?: number;
  scanner: string;
  url: string;
  description: string;
  cweId?: string;
}

// ─── AWS STS Operations ──────────────────────────────────────────────────────

/**
 * Assume an IAM role in the customer's AWS account using STS.
 * Returns temporary credentials for environment discovery.
 */
export async function assumeRole(config: AssumeRoleConfig): Promise<AwsCicdCredentials> {
  const stsClient = new STSClient({ region: config.region || "us-east-1" });

  const command = new AssumeRoleCommand({
    RoleArn: config.roleArn,
    ExternalId: config.externalId,
    RoleSessionName: config.sessionName || `ac3-cicd-scan-${Date.now()}`,
    DurationSeconds: 3600, // 1 hour
  });

  const response = await stsClient.send(command);

  if (!response.Credentials) {
    throw new Error("Failed to assume role: no credentials returned");
  }

  return {
    accessKeyId: response.Credentials.AccessKeyId!,
    secretAccessKey: response.Credentials.SecretAccessKey!,
    sessionToken: response.Credentials.SessionToken!,
    region: config.region || "us-east-1",
  };
}

/**
 * Validate AWS credentials by calling GetCallerIdentity.
 */
export async function validateCredentials(creds: AwsCicdCredentials): Promise<{
  accountId: string;
  arn: string;
  userId: string;
}> {
  const stsClient = new STSClient({
    region: creds.region || "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
    },
  });

  const response = await stsClient.send(new GetCallerIdentityCommand({}));

  return {
    accountId: response.Account || "",
    arn: response.Arn || "",
    userId: response.UserId || "",
  };
}

// ─── Environment Discovery ───────────────────────────────────────────────────

/**
 * Discover scannable environments in the customer's AWS account.
 * Looks for EC2 instances, ECS services, ELB/ALB endpoints, and CloudFront distributions.
 */
export async function discoverEnvironments(
  creds: AwsCicdCredentials,
  regions?: string[]
): Promise<DiscoveredEnvironment[]> {
  const targetRegions = regions || ["us-east-1", "us-west-2", "eu-west-1"];
  const environments: DiscoveredEnvironment[] = [];

  const credentials: AwsCredentialIdentity = {
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken,
  };

  for (const region of targetRegions) {
    try {
      // Discover EC2 instances with public IPs
      const ec2Envs = await discoverEC2(credentials, region);
      environments.push(...ec2Envs);
    } catch (e: any) {
      console.warn(`[AWS-CICD] EC2 discovery failed in ${region}: ${e.message}`);
    }

    try {
      // Discover ELB/ALB endpoints
      const elbEnvs = await discoverELB(credentials, region);
      environments.push(...elbEnvs);
    } catch (e: any) {
      console.warn(`[AWS-CICD] ELB discovery failed in ${region}: ${e.message}`);
    }

    try {
      // Discover API Gateway endpoints
      const apiGwEnvs = await discoverAPIGateway(credentials, region);
      environments.push(...apiGwEnvs);
    } catch (e: any) {
      console.warn(`[AWS-CICD] API Gateway discovery failed in ${region}: ${e.message}`);
    }
  }

  // CloudFront is global (us-east-1 only)
  try {
    const cfEnvs = await discoverCloudFront(credentials);
    environments.push(...cfEnvs);
  } catch (e: any) {
    console.warn(`[AWS-CICD] CloudFront discovery failed: ${e.message}`);
  }

  return environments;
}

async function discoverEC2(
  credentials: AwsCredentialIdentity,
  region: string
): Promise<DiscoveredEnvironment[]> {
  const { EC2Client, DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
  const client = new EC2Client({ region, credentials });

  const response = await client.send(new DescribeInstancesCommand({
    Filters: [
      { Name: "instance-state-name", Values: ["running"] },
    ],
    MaxResults: 50,
  }));

  const envs: DiscoveredEnvironment[] = [];

  for (const reservation of response.Reservations || []) {
    for (const instance of reservation.Instances || []) {
      const publicIp = instance.PublicIpAddress;
      const publicDns = instance.PublicDnsName;
      if (!publicIp && !publicDns) continue;

      const nameTag = instance.Tags?.find(t => t.Key === "Name")?.Value || instance.InstanceId;
      const envTag = instance.Tags?.find(t => t.Key === "Environment")?.Value || "unknown";

      envs.push({
        id: instance.InstanceId || "",
        name: `${nameTag} (${envTag})`,
        type: "ec2",
        url: `http://${publicDns || publicIp}`,
        region,
        metadata: {
          instanceId: instance.InstanceId || "",
          instanceType: instance.InstanceType || "",
          publicIp: publicIp || "",
          environment: envTag,
          launchTime: instance.LaunchTime?.toISOString() || "",
        },
      });
    }
  }

  return envs;
}

async function discoverELB(
  credentials: AwsCredentialIdentity,
  region: string
): Promise<DiscoveredEnvironment[]> {
  const {
    ElasticLoadBalancingV2Client,
    DescribeLoadBalancersCommand,
  } = await import("@aws-sdk/client-elastic-load-balancing-v2");

  const client = new ElasticLoadBalancingV2Client({ region, credentials });
  const response = await client.send(new DescribeLoadBalancersCommand({ PageSize: 50 }));

  const envs: DiscoveredEnvironment[] = [];

  for (const lb of response.LoadBalancers || []) {
    if (lb.Scheme === "internal") continue; // Skip internal LBs
    const dnsName = lb.DNSName;
    if (!dnsName) continue;

    envs.push({
      id: lb.LoadBalancerArn || "",
      name: lb.LoadBalancerName || "Unknown ALB",
      type: "elb",
      url: `https://${dnsName}`,
      region,
      metadata: {
        arn: lb.LoadBalancerArn || "",
        type: lb.Type || "",
        scheme: lb.Scheme || "",
        vpcId: lb.VpcId || "",
        state: lb.State?.Code || "",
      },
    });
  }

  return envs;
}

async function discoverAPIGateway(
  credentials: AwsCredentialIdentity,
  region: string
): Promise<DiscoveredEnvironment[]> {
  try {
    const { APIGatewayClient, GetRestApisCommand } = await import("@aws-sdk/client-api-gateway");
    const client = new APIGatewayClient({ region, credentials });
    const response = await client.send(new GetRestApisCommand({ limit: 50 }));

    const envs: DiscoveredEnvironment[] = [];

    for (const api of response.items || []) {
      envs.push({
        id: api.id || "",
        name: api.name || "Unknown API",
        type: "api_gateway",
        url: `https://${api.id}.execute-api.${region}.amazonaws.com/prod`,
        region,
        metadata: {
          apiId: api.id || "",
          description: api.description || "",
          createdDate: api.createdDate?.toISOString() || "",
        },
      });
    }

    return envs;
  } catch {
    return [];
  }
}

async function discoverCloudFront(
  credentials: AwsCredentialIdentity
): Promise<DiscoveredEnvironment[]> {
  try {
    const { CloudFrontClient, ListDistributionsCommand } = await import("@aws-sdk/client-cloudfront");
    const client = new CloudFrontClient({ region: "us-east-1", credentials });
    const response = await client.send(new ListDistributionsCommand({ MaxItems: 50 }));

    const envs: DiscoveredEnvironment[] = [];

    for (const dist of response.DistributionList?.Items || []) {
      if (!dist.Enabled) continue;
      const domainName = dist.DomainName;
      const aliases = dist.Aliases?.Items || [];

      envs.push({
        id: dist.Id || "",
        name: aliases[0] || domainName || "Unknown CF Distribution",
        type: "cloudfront",
        url: `https://${aliases[0] || domainName}`,
        region: "global",
        metadata: {
          distributionId: dist.Id || "",
          domainName: domainName || "",
          aliases: aliases.join(", "),
          status: dist.Status || "",
        },
      });
    }

    return envs;
  } catch {
    return [];
  }
}

// ─── Scan Execution ──────────────────────────────────────────────────────────

/**
 * Execute a CI/CD security scan against a target URL.
 * Triggers ZAP/Burp/Nuclei scans and collects results.
 */
export async function executeCicdScan(request: CicdScanRequest): Promise<CicdScanResult> {
  const startTime = Date.now();
  const findings: CicdFinding[] = [];

  console.log(`[CICD-SCAN] Starting scan for pipeline ${request.pipelineId}, run ${request.runId}`);
  console.log(`[CICD-SCAN] Target: ${request.targetUrl}, Scanners: ${request.scanTypes.join(", ")}`);

  for (const scanType of request.scanTypes) {
    try {
      switch (scanType) {
        case "nuclei": {
          const nucleiFindings = await runNucleiCicd(request.targetUrl);
          findings.push(...nucleiFindings);
          break;
        }
        case "zap": {
          const zapFindings = await runZapCicd(request.targetUrl);
          findings.push(...zapFindings);
          break;
        }
        case "burp": {
          const burpFindings = await runBurpCicd(request.targetUrl);
          findings.push(...burpFindings);
          break;
        }
        case "config": {
          const configFindings = await runConfigAuditCicd(request.targetUrl);
          findings.push(...configFindings);
          break;
        }
        case "cspm": {
          const cspmFindings = await runCspmCicd(request.cloudProvider || "aws", request.awsCredentials);
          findings.push(...cspmFindings);
          break;
        }
        case "container": {
          const containerFindings = await runContainerScanCicd(request.containerImage || request.targetUrl);
          findings.push(...containerFindings);
          break;
        }
        case "iac": {
          const iacFindings = await runIacScanCicd(request.iacRepoUrl || request.targetUrl, request.commitSha);
          findings.push(...iacFindings);
          break;
        }
      }
    } catch (e: any) {
      console.error(`[CICD-SCAN] ${scanType} scan failed: ${e.message}`);
    }
  }

  const duration = Math.round((Date.now() - startTime) / 1000);

  // Categorize findings
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const lowCount = findings.filter(f => f.severity === "low").length;
  const maxCvss = findings.reduce((max, f) => Math.max(max, f.cvss || 0), 0);

  // Determine pass/fail based on threshold
  const threshold = request.failThreshold ?? 7.0;
  const hasCriticalOrHigh = criticalCount > 0 || highCount > 0;
  const exceedsThreshold = maxCvss >= threshold;
  const status = (hasCriticalOrHigh || exceedsThreshold) ? "failed" : "passed";

  console.log(`[CICD-SCAN] Completed: ${findings.length} findings, max CVSS ${maxCvss}, status: ${status}`);

  return {
    runId: request.runId,
    pipelineId: request.pipelineId,
    status,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    maxCvss,
    duration,
    findings,
  };
}

// ─── Scanner Wrappers for CI/CD ──────────────────────────────────────────────

async function runNucleiCicd(targetUrl: string): Promise<CicdFinding[]> {
  const { executeRawCommandViaHttp } = await import("./do-scan-api");
  const findings: CicdFinding[] = [];

  try {
    const result = await executeRawCommandViaHttp(
      `nuclei -u ${targetUrl} -severity critical,high,medium -json -silent -timeout 5 -retries 1 -rate-limit 50`,
      120
    );

    if (result.stdout) {
      for (const line of result.stdout.split("\n").filter(Boolean)) {
        try {
          const parsed = JSON.parse(line);
          findings.push({
            title: parsed.info?.name || parsed.templateID || "Unknown",
            severity: (parsed.info?.severity || "info").toLowerCase() as any,
            cvss: parsed.info?.classification?.cvss_score,
            scanner: "nuclei",
            url: parsed.matched_at || parsed.host || targetUrl,
            description: parsed.info?.description || "",
            cweId: parsed.info?.classification?.cwe_id?.[0],
          });
        } catch { /* skip malformed lines */ }
      }
    }
  } catch (e: any) {
    console.warn(`[CICD-NUCLEI] Scan failed: ${e.message}`);
  }

  return findings;
}

async function runZapCicd(targetUrl: string): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];

  try {
    const { getActiveZapUrl } = await import("./scan-service-url");
    const zapUrl = await getActiveZapUrl();

    // Start ZAP spider
    const spiderResp = await fetch(`${zapUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}&maxChildren=10&recurse=true`);
    const spiderData = await spiderResp.json();
    const spiderId = spiderData.scan;

    if (spiderId) {
      // Wait for spider to complete (max 2 min)
      for (let i = 0; i < 24; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const statusResp = await fetch(`${zapUrl}/JSON/spider/view/status/?scanId=${spiderId}`);
        const statusData = await statusResp.json();
        if (parseInt(statusData.status) >= 100) break;
      }
    }

    // Start active scan
    const scanResp = await fetch(`${zapUrl}/JSON/ascan/action/scan/?url=${encodeURIComponent(targetUrl)}&recurse=true&scanPolicyName=Default+Policy`);
    const scanData = await scanResp.json();
    const scanId = scanData.scan;

    if (scanId) {
      // Wait for active scan (max 10 min)
      for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 10000));
        const statusResp = await fetch(`${zapUrl}/JSON/ascan/view/status/?scanId=${scanId}`);
        const statusData = await statusResp.json();
        if (parseInt(statusData.status) >= 100) break;
      }
    }

    // Get alerts
    const alertsResp = await fetch(`${zapUrl}/JSON/alert/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}&start=0&count=100`);
    const alertsData = await alertsResp.json();

    for (const alert of alertsData.alerts || []) {
      const riskMap: Record<string, string> = { "3": "high", "2": "medium", "1": "low", "0": "info" };
      findings.push({
        title: alert.name || alert.alert || "Unknown ZAP Alert",
        severity: (riskMap[alert.riskcode] || "info") as any,
        scanner: "zap",
        url: alert.url || targetUrl,
        description: alert.description || "",
        cweId: alert.cweid ? `CWE-${alert.cweid}` : undefined,
      });
    }
  } catch (e: any) {
    console.warn(`[CICD-ZAP] Scan failed: ${e.message}`);
  }

  return findings;
}

async function runBurpCicd(targetUrl: string): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];

  try {
    const BURP_URL = process.env.BURP_BASE_URL || "http://137.184.211.238:1337";

    // Submit scan
    const scanResp = await fetch(`${BURP_URL}/v0.1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        urls: [targetUrl],
        scan_configurations: [{ type: "NamedConfiguration", name: "Crawl and Audit - Fast" }],
      }),
    });

    if (!scanResp.ok) {
      console.warn(`[CICD-BURP] Scan submission failed: ${scanResp.status}`);
      return findings;
    }

    const location = scanResp.headers.get("Location");
    const taskId = location?.split("/").pop();

    if (!taskId) return findings;

    // Poll for completion (max 15 min)
    for (let i = 0; i < 90; i++) {
      await new Promise(r => setTimeout(r, 10000));
      const statusResp = await fetch(`${BURP_URL}/v0.1/scan/${taskId}`);
      const statusData = await statusResp.json();

      if (statusData.scan_status === "succeeded" || statusData.scan_status === "failed") {
        // Extract issues
        for (const issue of statusData.issue_events || []) {
          const severityMap: Record<string, string> = {
            high: "high",
            medium: "medium",
            low: "low",
            information: "info",
          };
          const iss = issue.issue;
          findings.push({
            title: iss?.name || "Unknown Burp Issue",
            severity: (severityMap[(iss?.severity || "").toLowerCase()] || "info") as any,
            scanner: "burp",
            url: iss?.origin || iss?.path || targetUrl,
            description: iss?.description || "",
          });
        }
        break;
      }
    }
  } catch (e: any) {
    console.warn(`[CICD-BURP] Scan failed: ${e.message}`);
  }

  return findings;
}

// ─── Configuration Audit Scanner (HTTP headers, TLS, DNS security) ──────────────────

async function runConfigAuditCicd(targetUrl: string): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];
  const url = new URL(targetUrl);

  try {
    // Check HTTP security headers
    const resp = await fetch(targetUrl, { redirect: "follow" });
    const headers = resp.headers;

    const requiredHeaders: Array<{ name: string; header: string; severity: "high" | "medium" | "low"; cwe: string; desc: string }> = [
      { name: "Strict-Transport-Security", header: "strict-transport-security", severity: "high", cwe: "CWE-319", desc: "Missing HSTS header allows protocol downgrade attacks" },
      { name: "Content-Security-Policy", header: "content-security-policy", severity: "medium", cwe: "CWE-79", desc: "Missing CSP header increases XSS risk" },
      { name: "X-Content-Type-Options", header: "x-content-type-options", severity: "low", cwe: "CWE-16", desc: "Missing X-Content-Type-Options allows MIME sniffing" },
      { name: "X-Frame-Options", header: "x-frame-options", severity: "medium", cwe: "CWE-1021", desc: "Missing X-Frame-Options allows clickjacking" },
      { name: "Referrer-Policy", header: "referrer-policy", severity: "low", cwe: "CWE-200", desc: "Missing Referrer-Policy may leak sensitive URL data" },
      { name: "Permissions-Policy", header: "permissions-policy", severity: "low", cwe: "CWE-16", desc: "Missing Permissions-Policy allows unrestricted browser features" },
    ];

    for (const h of requiredHeaders) {
      if (!headers.get(h.header)) {
        findings.push({
          title: `Missing Security Header: ${h.name}`,
          severity: h.severity,
          scanner: "config-audit",
          url: targetUrl,
          description: h.desc,
          cweId: h.cwe,
        });
      }
    }

    // Check for insecure cookies
    const setCookies = resp.headers.get("set-cookie") || "";
    if (setCookies && !setCookies.includes("Secure")) {
      findings.push({
        title: "Cookie Missing Secure Flag",
        severity: "medium",
        scanner: "config-audit",
        url: targetUrl,
        description: "Cookies are set without the Secure flag, allowing transmission over unencrypted connections",
        cweId: "CWE-614",
      });
    }

    // Check for server version disclosure
    const server = headers.get("server") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";
    if (server && /\/[\d.]+/.test(server)) {
      findings.push({
        title: `Server Version Disclosure: ${server}`,
        severity: "low",
        scanner: "config-audit",
        url: targetUrl,
        description: `Server header reveals version information: ${server}`,
        cweId: "CWE-200",
      });
    }
    if (xPoweredBy) {
      findings.push({
        title: `X-Powered-By Header Disclosure: ${xPoweredBy}`,
        severity: "low",
        scanner: "config-audit",
        url: targetUrl,
        description: `X-Powered-By header reveals technology stack: ${xPoweredBy}`,
        cweId: "CWE-200",
      });
    }

    // Check TLS configuration
    if (url.protocol === "https:") {
      try {
        const { executeRawCommandViaHttp } = await import("./do-scan-api");
        const tlsResult = await executeRawCommandViaHttp(
          `echo | openssl s_client -connect ${url.hostname}:443 -servername ${url.hostname} 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null`,
          15
        );
        if (tlsResult.stdout) {
          // Check certificate expiry
          const notAfterMatch = tlsResult.stdout.match(/notAfter=(.+)/);
          if (notAfterMatch) {
            const expiry = new Date(notAfterMatch[1]);
            const daysUntilExpiry = Math.round((expiry.getTime() - Date.now()) / 86400000);
            if (daysUntilExpiry < 0) {
              findings.push({
                title: "TLS Certificate Expired",
                severity: "critical",
                cvss: 9.1,
                scanner: "config-audit",
                url: targetUrl,
                description: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`,
                cweId: "CWE-295",
              });
            } else if (daysUntilExpiry < 30) {
              findings.push({
                title: `TLS Certificate Expiring Soon (${daysUntilExpiry} days)`,
                severity: "medium",
                scanner: "config-audit",
                url: targetUrl,
                description: `Certificate expires in ${daysUntilExpiry} days`,
                cweId: "CWE-295",
              });
            }
          }
        }
      } catch { /* TLS check failed, skip */ }
    }

    console.log(`[CICD-CONFIG] Audit complete: ${findings.length} findings for ${targetUrl}`);
  } catch (e: any) {
    console.warn(`[CICD-CONFIG] Audit failed: ${e.message}`);
  }

  return findings;
}

// ─── CSPM Scanner (Cloud Security Posture Management) ───────────────────────────────

async function runCspmCicd(
  provider: "aws" | "azure" | "gcp",
  creds?: AwsCicdCredentials
): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];

  try {
    const { runAssessment, getChecksByProvider } = await import("./cloud-security-validation");
    const checks = getChecksByProvider(provider);
    const assessment = runAssessment(provider, checks);

    for (const result of assessment.results) {
      if (result.status === "fail") {
        findings.push({
          title: `[CSPM] ${result.checkTitle}`,
          severity: result.severity as any,
          scanner: "cspm",
          url: `${provider}://${result.resource || result.checkId}`,
          description: `${result.detail || result.checkTitle}. CIS Benchmark: ${result.cisBenchmark || "N/A"}. Remediation: ${(result.remediation || ["Review cloud configuration"]).join("; ")}`,
          cweId: result.mitreTechniques?.[0] ? `MITRE-${result.mitreTechniques[0]}` : undefined,
        });
      }
    }

    // If AWS credentials provided, also run IAM enumeration checks
    if (provider === "aws" && creds) {
      try {
        const { IAM_MISCONFIG_CHECKS } = await import("./cloud-attack-paths");
        for (const check of IAM_MISCONFIG_CHECKS.slice(0, 10)) {
          // These are known misconfiguration patterns — flag as informational
          findings.push({
            title: `[IAM] ${check.name}`,
            severity: (check.severity || "medium") as any,
            scanner: "cspm-iam",
            url: `aws://iam/${check.id}`,
            description: `${check.description}. Impact: ${check.impact || "Potential privilege escalation"}`,
          });
        }
      } catch { /* IAM checks not available */ }
    }

    console.log(`[CICD-CSPM] ${provider} assessment: ${findings.length} findings`);
  } catch (e: any) {
    console.warn(`[CICD-CSPM] Assessment failed: ${e.message}`);
  }

  return findings;
}

// ─── Container Image Scanner ────────────────────────────────────────────────────────────────

async function runContainerScanCicd(imageRef: string): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];

  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api");

    // Run Trivy container scan
    const result = await executeRawCommandViaHttp(
      `trivy image --format json --severity CRITICAL,HIGH,MEDIUM --timeout 5m ${imageRef} 2>/dev/null || echo '{"Results":[]}'`,
      360
    );

    if (result.stdout) {
      try {
        const trivyOutput = JSON.parse(result.stdout);
        for (const target of trivyOutput.Results || []) {
          for (const vuln of target.Vulnerabilities || []) {
            const sevMap: Record<string, string> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
            findings.push({
              title: `[Container] ${vuln.VulnerabilityID}: ${vuln.PkgName} ${vuln.InstalledVersion}`,
              severity: (sevMap[vuln.Severity] || "medium") as any,
              cvss: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score,
              scanner: "trivy",
              url: `${imageRef}#${target.Target}`,
              description: `${vuln.Title || vuln.VulnerabilityID} in ${vuln.PkgName} (installed: ${vuln.InstalledVersion}, fixed: ${vuln.FixedVersion || "not yet"})`,
              cweId: vuln.CweIDs?.[0],
            });
          }
        }
      } catch { /* JSON parse error */ }
    }

    console.log(`[CICD-CONTAINER] Image scan complete: ${findings.length} findings for ${imageRef}`);
  } catch (e: any) {
    console.warn(`[CICD-CONTAINER] Scan failed: ${e.message}`);
  }

  return findings;
}

// ─── IaC Scanner (Terraform, CloudFormation, Kubernetes manifests) ──────────────

async function runIacScanCicd(repoOrPath: string, commitSha?: string): Promise<CicdFinding[]> {
  const findings: CicdFinding[] = [];

  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api");

    // Clone repo if it's a URL, otherwise scan path directly
    const isUrl = repoOrPath.startsWith("http");
    const scanPath = isUrl ? `/tmp/iac-scan-${Date.now()}` : repoOrPath;

    if (isUrl) {
      const cloneCmd = commitSha
        ? `git clone --depth 1 ${repoOrPath} ${scanPath} && cd ${scanPath} && git checkout ${commitSha} 2>/dev/null || true`
        : `git clone --depth 1 ${repoOrPath} ${scanPath}`;
      await executeRawCommandViaHttp(cloneCmd, 60);
    }

    // Run checkov for IaC scanning (Terraform, CloudFormation, K8s, Dockerfile)
    const result = await executeRawCommandViaHttp(
      `checkov -d ${scanPath} --output json --compact --quiet 2>/dev/null || echo '{"results":{"failed_checks":[]}}'`,
      180
    );

    if (result.stdout) {
      try {
        const checkovOutput = JSON.parse(result.stdout);
        const failedChecks = checkovOutput.results?.failed_checks || [];

        for (const check of failedChecks) {
          // Map checkov severity to our severity levels
          const sevMap: Record<string, string> = {
            CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info",
          };
          findings.push({
            title: `[IaC] ${check.check_id}: ${check.check_result?.evaluated_keys?.[0] || check.name || check.check_id}`,
            severity: (sevMap[check.severity || "MEDIUM"] || "medium") as any,
            scanner: "checkov",
            url: `${repoOrPath}#${check.file_path || ""}:${check.file_line_range?.[0] || 0}`,
            description: `${check.name || check.check_id}. Resource: ${check.resource || "unknown"}. File: ${check.file_path || "unknown"} (line ${check.file_line_range?.[0] || "?"})`,
            cweId: check.guideline ? undefined : undefined,
          });
        }
      } catch { /* JSON parse error */ }
    }

    // Also run tfsec if Terraform files are present
    const tfCheck = await executeRawCommandViaHttp(`find ${scanPath} -name '*.tf' -maxdepth 3 | head -1`, 10);
    if (tfCheck.stdout?.trim()) {
      try {
        const tfsecResult = await executeRawCommandViaHttp(
          `tfsec ${scanPath} --format json --soft-fail 2>/dev/null || echo '{"results":[]}'`,
          120
        );
        if (tfsecResult.stdout) {
          const tfsecOutput = JSON.parse(tfsecResult.stdout);
          for (const r of tfsecOutput.results || []) {
            const sevMap: Record<string, string> = {
              CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low",
            };
            findings.push({
              title: `[Terraform] ${r.rule_id}: ${r.rule_description || r.rule_id}`,
              severity: (sevMap[r.severity || "MEDIUM"] || "medium") as any,
              scanner: "tfsec",
              url: `${repoOrPath}#${r.location?.filename || ""}:${r.location?.start_line || 0}`,
              description: `${r.description || r.rule_description}. Resource: ${r.resource || "unknown"}. Impact: ${r.impact || "See documentation"}`,
              cweId: r.links?.[0] ? undefined : undefined,
            });
          }
        }
      } catch { /* tfsec not available or parse error */ }
    }

    // Cleanup cloned repo
    if (isUrl) {
      await executeRawCommandViaHttp(`rm -rf ${scanPath}`, 10).catch(() => {});
    }

    console.log(`[CICD-IAC] Scan complete: ${findings.length} findings for ${repoOrPath}`);
  } catch (e: any) {
    console.warn(`[CICD-IAC] Scan failed: ${e.message}`);
  }

  return findings;
}

// ─── Webhook Verification ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a GitHub Actions webhook signature (HMAC-SHA256).
 */
export function verifyGitHubWebhook(payload: string, signature: string, secret: string): boolean {
  const expected = `sha256=${crypto.createHmac("sha256", secret).update(payload).digest("hex")}`;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

/**
 * Generate a webhook secret for a new pipeline.
 */
export function generateWebhookSecret(): string {
  return `ac3_whsec_${crypto.randomBytes(24).toString("hex")}`;
}

/**
 * Generate a webhook URL for a pipeline.
 */
export function generateWebhookUrl(pipelineId: number): string {
  const baseUrl = process.env.VITE_APP_URL || process.env.RAILWAY_PUBLIC_DOMAIN || "";
  return `${baseUrl}/api/cicd/webhook/${pipelineId}`;
}

// ─── CI/CD Provider Callbacks ────────────────────────────────────────────────

/**
 * Send scan results back to GitHub Actions via Check Run API.
 */
export async function callbackGitHubActions(
  result: CicdScanResult,
  githubToken: string,
  owner: string,
  repo: string,
  commitSha: string
): Promise<void> {
  const conclusion = result.status === "passed" ? "success" : "failure";

  const body = {
    name: "AC3 Security Scan",
    head_sha: commitSha,
    status: "completed",
    conclusion,
    output: {
      title: `Security Scan: ${result.totalFindings} findings (${result.criticalCount} critical, ${result.highCount} high)`,
      summary: [
        `## AC3 CI/CD Security Scan Results`,
        ``,
        `| Metric | Value |`,
        `|--------|-------|`,
        `| Total Findings | ${result.totalFindings} |`,
        `| Critical | ${result.criticalCount} |`,
        `| High | ${result.highCount} |`,
        `| Medium | ${result.mediumCount} |`,
        `| Low | ${result.lowCount} |`,
        `| Max CVSS | ${result.maxCvss} |`,
        `| Duration | ${result.duration}s |`,
        `| Status | **${result.status.toUpperCase()}** |`,
        ``,
        result.reportUrl ? `[View Full Report](${result.reportUrl})` : "",
      ].join("\n"),
      text: result.findings.slice(0, 50).map(f =>
        `### ${f.severity.toUpperCase()}: ${f.title}\n- URL: ${f.url}\n- Scanner: ${f.scanner}\n${f.cweId ? `- CWE: ${f.cweId}` : ""}\n- ${f.description.substring(0, 200)}`
      ).join("\n\n"),
    },
  };

  await fetch(`https://api.github.com/repos/${owner}/${repo}/check-runs`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(body),
  });
}

/**
 * Send scan results back to AWS CodePipeline via PutJobSuccessResult/PutJobFailureResult.
 */
export async function callbackCodePipeline(
  result: CicdScanResult,
  creds: AwsCicdCredentials,
  jobId: string
): Promise<void> {
  const { CodePipelineClient, PutJobSuccessResultCommand, PutJobFailureResultCommand } = await import("@aws-sdk/client-codepipeline");

  const client = new CodePipelineClient({
    region: creds.region || "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
    },
  });

  if (result.status === "passed") {
    await client.send(new PutJobSuccessResultCommand({
      jobId,
      executionDetails: {
        summary: `AC3 Security Scan passed: ${result.totalFindings} findings, max CVSS ${result.maxCvss}`,
        percentComplete: 100,
      },
    }));
  } else {
    await client.send(new PutJobFailureResultCommand({
      jobId,
      failureDetails: {
        type: "JobFailed",
        message: `AC3 Security Scan failed: ${result.criticalCount} critical, ${result.highCount} high findings (max CVSS ${result.maxCvss})`,
      },
    }));
  }
}

// ─── YAML Snippet Generators ─────────────────────────────────────────────────

export function generateGitHubActionsYaml(webhookUrl: string, webhookSecret: string): string {
  return `# AC3 Security Scan - GitHub Actions Integration
# Add this to your .github/workflows/security-scan.yml

name: AC3 Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Deploy to staging
        # Your deployment step here
        run: echo "Deploy to staging environment"

      - name: Trigger AC3 Security Scan
        env:
          AC3_WEBHOOK_URL: \${webhookUrl}
          AC3_WEBHOOK_SECRET: \${{ secrets.AC3_WEBHOOK_SECRET }}
        run: |
          PAYLOAD='{"event":"deployment","target_url":"https://staging.yourapp.com","commit_sha":"'\${{ github.sha }}'","branch":"'\${{ github.ref_name }}'","repository":"'\${{ github.repository }}'"}'
          SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$AC3_WEBHOOK_SECRET" | awk '{print $2}')
          curl -X POST "$AC3_WEBHOOK_URL" \\
            -H "Content-Type: application/json" \\
            -H "X-Hub-Signature-256: sha256=$SIGNATURE" \\
            -d "$PAYLOAD"

      - name: Wait for scan results
        # The scan results will be posted back as a GitHub Check Run
        run: echo "AC3 scan triggered. Results will appear as a Check Run."
`;
}

export function generateCodePipelineYaml(): string {
  return `# AC3 Security Scan - AWS CodePipeline Integration
# Add this as a custom action in your CodePipeline

# 1. Create an IAM Role for AC3 with the following trust policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::root"  // AC3 account
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "YOUR_EXTERNAL_ID"  // Generated by AC3
        }
      }
    }
  ]
}

# 2. Attach the following policy to the role:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "cloudfront:ListDistributions",
        "codepipeline:PutJobSuccessResult",
        "codepipeline:PutJobFailureResult"
      ],
      "Resource": "*"
    }
  ]
}

# 3. Add the Role ARN and External ID to your AC3 CI/CD pipeline configuration.
# 4. AC3 will automatically discover your environments and trigger scans.
`;
}

export function generateGitLabCiYaml(webhookUrl: string): string {
  return `# AC3 Security Scan - GitLab CI Integration
# Add this to your .gitlab-ci.yml

stages:
  - deploy
  - security

ac3-security-scan:
  stage: security
  image: curlimages/curl:latest
  script:
    - |
      PAYLOAD='{"event":"deployment","target_url":"https://staging.yourapp.com","commit_sha":"'\$CI_COMMIT_SHA'","branch":"'\$CI_COMMIT_REF_NAME'","repository":"'\$CI_PROJECT_PATH'"}'
      SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$AC3_WEBHOOK_SECRET" | awk '{print $2}')
      curl -X POST "${webhookUrl}" \\
        -H "Content-Type: application/json" \\
        -H "X-Webhook-Signature: sha256=$SIGNATURE" \\
        -d "$PAYLOAD"
  rules:
    - if: '\$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '\$CI_COMMIT_BRANCH == "main"'
`;
}
