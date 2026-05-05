import "./chunk-KFQGP6VL.js";

// server/lib/aws-cicd-connector.ts
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import crypto from "crypto";
async function assumeRole(config) {
  const stsClient = new STSClient({ region: config.region || "us-east-1" });
  const command = new AssumeRoleCommand({
    RoleArn: config.roleArn,
    ExternalId: config.externalId,
    RoleSessionName: config.sessionName || `ac3-cicd-scan-${Date.now()}`,
    DurationSeconds: 3600
    // 1 hour
  });
  const response = await stsClient.send(command);
  if (!response.Credentials) {
    throw new Error("Failed to assume role: no credentials returned");
  }
  return {
    accessKeyId: response.Credentials.AccessKeyId,
    secretAccessKey: response.Credentials.SecretAccessKey,
    sessionToken: response.Credentials.SessionToken,
    region: config.region || "us-east-1"
  };
}
async function validateCredentials(creds) {
  const stsClient = new STSClient({
    region: creds.region || "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken
    }
  });
  const response = await stsClient.send(new GetCallerIdentityCommand({}));
  return {
    accountId: response.Account || "",
    arn: response.Arn || "",
    userId: response.UserId || ""
  };
}
async function discoverEnvironments(creds, regions) {
  const targetRegions = regions || ["us-east-1", "us-west-2", "eu-west-1"];
  const environments = [];
  const credentials = {
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken
  };
  for (const region of targetRegions) {
    try {
      const ec2Envs = await discoverEC2(credentials, region);
      environments.push(...ec2Envs);
    } catch (e) {
      console.warn(`[AWS-CICD] EC2 discovery failed in ${region}: ${e.message}`);
    }
    try {
      const elbEnvs = await discoverELB(credentials, region);
      environments.push(...elbEnvs);
    } catch (e) {
      console.warn(`[AWS-CICD] ELB discovery failed in ${region}: ${e.message}`);
    }
    try {
      const apiGwEnvs = await discoverAPIGateway(credentials, region);
      environments.push(...apiGwEnvs);
    } catch (e) {
      console.warn(`[AWS-CICD] API Gateway discovery failed in ${region}: ${e.message}`);
    }
  }
  try {
    const cfEnvs = await discoverCloudFront(credentials);
    environments.push(...cfEnvs);
  } catch (e) {
    console.warn(`[AWS-CICD] CloudFront discovery failed: ${e.message}`);
  }
  return environments;
}
async function discoverEC2(credentials, region) {
  const { EC2Client, DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
  const client = new EC2Client({ region, credentials });
  const response = await client.send(new DescribeInstancesCommand({
    Filters: [
      { Name: "instance-state-name", Values: ["running"] }
    ],
    MaxResults: 50
  }));
  const envs = [];
  for (const reservation of response.Reservations || []) {
    for (const instance of reservation.Instances || []) {
      const publicIp = instance.PublicIpAddress;
      const publicDns = instance.PublicDnsName;
      if (!publicIp && !publicDns) continue;
      const nameTag = instance.Tags?.find((t) => t.Key === "Name")?.Value || instance.InstanceId;
      const envTag = instance.Tags?.find((t) => t.Key === "Environment")?.Value || "unknown";
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
          launchTime: instance.LaunchTime?.toISOString() || ""
        }
      });
    }
  }
  return envs;
}
async function discoverELB(credentials, region) {
  const {
    ElasticLoadBalancingV2Client,
    DescribeLoadBalancersCommand
  } = await import("@aws-sdk/client-elastic-load-balancing-v2");
  const client = new ElasticLoadBalancingV2Client({ region, credentials });
  const response = await client.send(new DescribeLoadBalancersCommand({ PageSize: 50 }));
  const envs = [];
  for (const lb of response.LoadBalancers || []) {
    if (lb.Scheme === "internal") continue;
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
        state: lb.State?.Code || ""
      }
    });
  }
  return envs;
}
async function discoverAPIGateway(credentials, region) {
  try {
    const { APIGatewayClient, GetRestApisCommand } = await import("@aws-sdk/client-api-gateway");
    const client = new APIGatewayClient({ region, credentials });
    const response = await client.send(new GetRestApisCommand({ limit: 50 }));
    const envs = [];
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
          createdDate: api.createdDate?.toISOString() || ""
        }
      });
    }
    return envs;
  } catch {
    return [];
  }
}
async function discoverCloudFront(credentials) {
  try {
    const { CloudFrontClient, ListDistributionsCommand } = await import("@aws-sdk/client-cloudfront");
    const client = new CloudFrontClient({ region: "us-east-1", credentials });
    const response = await client.send(new ListDistributionsCommand({ MaxItems: 50 }));
    const envs = [];
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
          status: dist.Status || ""
        }
      });
    }
    return envs;
  } catch {
    return [];
  }
}
function validateTargetUrl(targetUrl, allowedDomains) {
  if (!allowedDomains || allowedDomains.length === 0) return { valid: true };
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname.toLowerCase();
    const matched = allowedDomains.some((domain) => {
      const d = domain.toLowerCase().replace(/^\*\./, "");
      return hostname === d || hostname.endsWith(`.${d}`);
    });
    if (!matched) return { valid: false, reason: `Domain ${hostname} is not in the allowlist: ${allowedDomains.join(", ")}` };
    return { valid: true };
  } catch {
    return { valid: false, reason: `Invalid URL: ${targetUrl}` };
  }
}
async function scanServerPreFlight() {
  try {
    const { checkDoScanServiceHealth } = await import("./do-scan-api-5H2UCULX.js");
    const health = await checkDoScanServiceHealth();
    if (!health.healthy) {
      return { healthy: false, error: health.error || "Scan server is unreachable" };
    }
    return { healthy: true };
  } catch (e) {
    return { healthy: false, error: e.message };
  }
}
async function executeCicdScan(request) {
  const startTime = Date.now();
  const findings = [];
  console.log(`[CICD-SCAN] Starting scan for pipeline ${request.pipelineId}, run ${request.runId}`);
  console.log(`[CICD-SCAN] Target: ${request.targetUrl}, Scanners: ${request.scanTypes.join(", ")}`);
  const urlCheck = validateTargetUrl(request.targetUrl, request.allowedDomains);
  if (!urlCheck.valid) {
    console.warn(`[CICD-SCAN] Target URL rejected: ${urlCheck.reason}`);
    return {
      runId: request.runId,
      pipelineId: request.pipelineId,
      status: "error",
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      maxCvss: 0,
      duration: 0,
      findings: [{ title: `Scan blocked: ${urlCheck.reason}`, severity: "info", scanner: "system", url: request.targetUrl, description: urlCheck.reason || "" }]
    };
  }
  const needsScanServer = request.scanTypes.some((t) => ["nuclei", "zap", "burp", "container", "iac", "secrets"].includes(t));
  if (needsScanServer) {
    const preFlight = await scanServerPreFlight();
    if (!preFlight.healthy) {
      console.error(`[CICD-SCAN] Pre-flight failed: ${preFlight.error}`);
      return {
        runId: request.runId,
        pipelineId: request.pipelineId,
        status: "error",
        totalFindings: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        maxCvss: 0,
        duration: 0,
        findings: [{ title: `Scan server unavailable: ${preFlight.error}`, severity: "info", scanner: "system", url: request.targetUrl, description: `Pre-flight health check failed: ${preFlight.error}` }]
      };
    }
    console.log(`[CICD-SCAN] Pre-flight passed \u2014 scan server is healthy`);
  }
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
          const iacFindings = await runIacScanCicd(
            request.iacRepoUrl || request.targetUrl,
            request.commitSha,
            request.incrementalOnly ? request.branch : void 0
          );
          findings.push(...iacFindings);
          break;
        }
        case "secrets": {
          const secretFindings = await runSecretScanCicd(request.iacRepoUrl || request.targetUrl, request.commitSha);
          findings.push(...secretFindings);
          break;
        }
      }
    } catch (e) {
      console.error(`[CICD-SCAN] ${scanType} scan failed: ${e.message}`);
    }
  }
  const duration = Math.round((Date.now() - startTime) / 1e3);
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  const maxCvss = findings.reduce((max, f) => Math.max(max, f.cvss || 0), 0);
  const threshold = request.failThreshold ?? 7;
  const hasCriticalOrHigh = criticalCount > 0 || highCount > 0;
  const exceedsThreshold = maxCvss >= threshold;
  const status = hasCriticalOrHigh || exceedsThreshold ? "failed" : "passed";
  console.log(`[CICD-SCAN] Completed: ${findings.length} findings, max CVSS ${maxCvss}, status: ${status}`);
  let threatContext = null;
  try {
    const { correlateCicdFindings } = await import("./cicd-threat-correlator-FCSAYNCN.js");
    threatContext = await correlateCicdFindings(findings);
    console.log(`[CICD-SCAN] Threat intel: ${threatContext.summary.uniqueActorsMatched} actors matched, ${threatContext.summary.severityBoostedCount} findings boosted, exposure score: ${threatContext.summary.actorExposureScore}`);
    if (threatContext.enrichedFindings?.length) {
      for (let i = 0; i < findings.length && i < threatContext.enrichedFindings.length; i++) {
        findings[i].severity = threatContext.enrichedFindings[i].severity;
        if (threatContext.enrichedFindings[i].cvss === void 0 && threatContext.enrichedFindings[i].severityBoosted) {
          const severityCvss = { critical: 9.5, high: 8, medium: 5.5, low: 3, info: 0 };
          findings[i].cvss = severityCvss[findings[i].severity] || findings[i].cvss;
        }
      }
    }
  } catch (e) {
    console.warn(`[CICD-SCAN] Threat intel correlation failed (non-blocking): ${e.message}`);
  }
  let newFindings = findings.length;
  let fixedFindings = 0;
  let baselineCompared = false;
  if (request.baselineId) {
    try {
      const baselineResult = await compareWithBaseline(request.pipelineId, request.baselineId, findings);
      newFindings = baselineResult.newCount;
      fixedFindings = baselineResult.fixedCount;
      baselineCompared = true;
      console.log(`[CICD-SCAN] Baseline comparison: ${newFindings} new, ${fixedFindings} fixed`);
    } catch (e) {
      console.warn(`[CICD-SCAN] Baseline comparison failed: ${e.message}`);
    }
  }
  let sbomUrl;
  let sbomPackageCount;
  if (request.generateSbom && request.scanTypes.includes("container")) {
    try {
      const sbomResult = await generateSbom(request.containerImage || request.targetUrl);
      sbomUrl = sbomResult.url;
      sbomPackageCount = sbomResult.packageCount;
      console.log(`[CICD-SCAN] SBOM generated: ${sbomPackageCount} packages`);
    } catch (e) {
      console.warn(`[CICD-SCAN] SBOM generation failed: ${e.message}`);
    }
  }
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
    newFindings,
    fixedFindings,
    baselineCompared,
    sbomUrl,
    sbomPackageCount,
    threatContext
  };
}
async function runNucleiCicd(targetUrl) {
  const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
  const findings = [];
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
            severity: (parsed.info?.severity || "info").toLowerCase(),
            cvss: parsed.info?.classification?.cvss_score,
            scanner: "nuclei",
            url: parsed.matched_at || parsed.host || targetUrl,
            description: parsed.info?.description || "",
            cweId: parsed.info?.classification?.cwe_id?.[0]
          });
        } catch {
        }
      }
    }
  } catch (e) {
    console.warn(`[CICD-NUCLEI] Scan failed: ${e.message}`);
  }
  return findings;
}
async function runZapCicd(targetUrl) {
  const findings = [];
  try {
    const { getActiveZapUrl } = await import("./scan-service-url-5PU2PCMP.js");
    const zapUrl = await getActiveZapUrl();
    const spiderResp = await fetch(`${zapUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}&maxChildren=10&recurse=true`);
    const spiderData = await spiderResp.json();
    const spiderId = spiderData.scan;
    if (spiderId) {
      for (let i = 0; i < 24; i++) {
        await new Promise((r) => setTimeout(r, 5e3));
        const statusResp = await fetch(`${zapUrl}/JSON/spider/view/status/?scanId=${spiderId}`);
        const statusData = await statusResp.json();
        if (parseInt(statusData.status) >= 100) break;
      }
    }
    const scanResp = await fetch(`${zapUrl}/JSON/ascan/action/scan/?url=${encodeURIComponent(targetUrl)}&recurse=true&scanPolicyName=Default+Policy`);
    const scanData = await scanResp.json();
    const scanId = scanData.scan;
    if (scanId) {
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 1e4));
        const statusResp = await fetch(`${zapUrl}/JSON/ascan/view/status/?scanId=${scanId}`);
        const statusData = await statusResp.json();
        if (parseInt(statusData.status) >= 100) break;
      }
    }
    const alertsResp = await fetch(`${zapUrl}/JSON/alert/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}&start=0&count=100`);
    const alertsData = await alertsResp.json();
    for (const alert of alertsData.alerts || []) {
      const riskMap = { "3": "high", "2": "medium", "1": "low", "0": "info" };
      findings.push({
        title: alert.name || alert.alert || "Unknown ZAP Alert",
        severity: riskMap[alert.riskcode] || "info",
        scanner: "zap",
        url: alert.url || targetUrl,
        description: alert.description || "",
        cweId: alert.cweid ? `CWE-${alert.cweid}` : void 0
      });
    }
  } catch (e) {
    console.warn(`[CICD-ZAP] Scan failed: ${e.message}`);
  }
  return findings;
}
async function runBurpCicd(targetUrl) {
  const findings = [];
  try {
    const BURP_URL = process.env.BURP_BASE_URL || "http://137.184.211.238:1337";
    const scanResp = await fetch(`${BURP_URL}/v0.1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        urls: [targetUrl],
        scan_configurations: [{ type: "NamedConfiguration", name: "Crawl and Audit - Fast" }]
      })
    });
    if (!scanResp.ok) {
      console.warn(`[CICD-BURP] Scan submission failed: ${scanResp.status}`);
      return findings;
    }
    const location = scanResp.headers.get("Location");
    const taskId = location?.split("/").pop();
    if (!taskId) return findings;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 1e4));
      const statusResp = await fetch(`${BURP_URL}/v0.1/scan/${taskId}`);
      const statusData = await statusResp.json();
      if (statusData.scan_status === "succeeded" || statusData.scan_status === "failed") {
        for (const issue of statusData.issue_events || []) {
          const severityMap = {
            high: "high",
            medium: "medium",
            low: "low",
            information: "info"
          };
          const iss = issue.issue;
          findings.push({
            title: iss?.name || "Unknown Burp Issue",
            severity: severityMap[(iss?.severity || "").toLowerCase()] || "info",
            scanner: "burp",
            url: iss?.origin || iss?.path || targetUrl,
            description: iss?.description || ""
          });
        }
        break;
      }
    }
  } catch (e) {
    console.warn(`[CICD-BURP] Scan failed: ${e.message}`);
  }
  return findings;
}
async function runConfigAuditCicd(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  try {
    const resp = await fetch(targetUrl, { redirect: "follow" });
    const headers = resp.headers;
    const requiredHeaders = [
      { name: "Strict-Transport-Security", header: "strict-transport-security", severity: "high", cwe: "CWE-319", desc: "Missing HSTS header allows protocol downgrade attacks" },
      { name: "Content-Security-Policy", header: "content-security-policy", severity: "medium", cwe: "CWE-79", desc: "Missing CSP header increases XSS risk" },
      { name: "X-Content-Type-Options", header: "x-content-type-options", severity: "low", cwe: "CWE-16", desc: "Missing X-Content-Type-Options allows MIME sniffing" },
      { name: "X-Frame-Options", header: "x-frame-options", severity: "medium", cwe: "CWE-1021", desc: "Missing X-Frame-Options allows clickjacking" },
      { name: "Referrer-Policy", header: "referrer-policy", severity: "low", cwe: "CWE-200", desc: "Missing Referrer-Policy may leak sensitive URL data" },
      { name: "Permissions-Policy", header: "permissions-policy", severity: "low", cwe: "CWE-16", desc: "Missing Permissions-Policy allows unrestricted browser features" }
    ];
    for (const h of requiredHeaders) {
      if (!headers.get(h.header)) {
        findings.push({
          title: `Missing Security Header: ${h.name}`,
          severity: h.severity,
          scanner: "config-audit",
          url: targetUrl,
          description: h.desc,
          cweId: h.cwe
        });
      }
    }
    const setCookies = resp.headers.get("set-cookie") || "";
    if (setCookies && !setCookies.includes("Secure")) {
      findings.push({
        title: "Cookie Missing Secure Flag",
        severity: "medium",
        scanner: "config-audit",
        url: targetUrl,
        description: "Cookies are set without the Secure flag, allowing transmission over unencrypted connections",
        cweId: "CWE-614"
      });
    }
    const server = headers.get("server") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";
    if (server && /\/[\d.]+/.test(server)) {
      findings.push({
        title: `Server Version Disclosure: ${server}`,
        severity: "low",
        scanner: "config-audit",
        url: targetUrl,
        description: `Server header reveals version information: ${server}`,
        cweId: "CWE-200"
      });
    }
    if (xPoweredBy) {
      findings.push({
        title: `X-Powered-By Header Disclosure: ${xPoweredBy}`,
        severity: "low",
        scanner: "config-audit",
        url: targetUrl,
        description: `X-Powered-By header reveals technology stack: ${xPoweredBy}`,
        cweId: "CWE-200"
      });
    }
    if (url.protocol === "https:") {
      try {
        const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
        const tlsResult = await executeRawCommandViaHttp(
          `echo | openssl s_client -connect ${url.hostname}:443 -servername ${url.hostname} 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null`,
          15
        );
        if (tlsResult.stdout) {
          const notAfterMatch = tlsResult.stdout.match(/notAfter=(.+)/);
          if (notAfterMatch) {
            const expiry = new Date(notAfterMatch[1]);
            const daysUntilExpiry = Math.round((expiry.getTime() - Date.now()) / 864e5);
            if (daysUntilExpiry < 0) {
              findings.push({
                title: "TLS Certificate Expired",
                severity: "critical",
                cvss: 9.1,
                scanner: "config-audit",
                url: targetUrl,
                description: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`,
                cweId: "CWE-295"
              });
            } else if (daysUntilExpiry < 30) {
              findings.push({
                title: `TLS Certificate Expiring Soon (${daysUntilExpiry} days)`,
                severity: "medium",
                scanner: "config-audit",
                url: targetUrl,
                description: `Certificate expires in ${daysUntilExpiry} days`,
                cweId: "CWE-295"
              });
            }
          }
        }
      } catch {
      }
    }
    console.log(`[CICD-CONFIG] Audit complete: ${findings.length} findings for ${targetUrl}`);
  } catch (e) {
    console.warn(`[CICD-CONFIG] Audit failed: ${e.message}`);
  }
  return findings;
}
async function runCspmCicd(provider, creds) {
  const findings = [];
  try {
    const { runAssessment, getChecksByProvider } = await import("./cloud-security-validation-K2B3T3NB.js");
    const checks = getChecksByProvider(provider);
    const assessment = runAssessment(provider, checks);
    for (const result of assessment.results) {
      if (result.status === "fail") {
        findings.push({
          title: `[CSPM] ${result.checkTitle}`,
          severity: result.severity,
          scanner: "cspm",
          url: `${provider}://${result.resource || result.checkId}`,
          description: `${result.detail || result.checkTitle}. CIS Benchmark: ${result.cisBenchmark || "N/A"}. Remediation: ${(result.remediation || ["Review cloud configuration"]).join("; ")}`,
          cweId: result.mitreTechniques?.[0] ? `MITRE-${result.mitreTechniques[0]}` : void 0
        });
      }
    }
    if (provider === "aws" && creds) {
      try {
        const { IAM_MISCONFIG_CHECKS } = await import("./cloud-attack-paths-LPWJQ5FI.js");
        for (const check of IAM_MISCONFIG_CHECKS.slice(0, 10)) {
          findings.push({
            title: `[IAM] ${check.name}`,
            severity: check.severity || "medium",
            scanner: "cspm-iam",
            url: `aws://iam/${check.id}`,
            description: `${check.description}. Impact: ${check.impact || "Potential privilege escalation"}`
          });
        }
      } catch {
      }
    }
    console.log(`[CICD-CSPM] ${provider} assessment: ${findings.length} findings`);
  } catch (e) {
    console.warn(`[CICD-CSPM] Assessment failed: ${e.message}`);
  }
  return findings;
}
async function runContainerScanCicd(imageRef) {
  const findings = [];
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
    const result = await executeRawCommandViaHttp(
      `trivy image --format json --severity CRITICAL,HIGH,MEDIUM --timeout 5m ${imageRef} 2>/dev/null || echo '{"Results":[]}'`,
      360
    );
    if (result.stdout) {
      try {
        const trivyOutput = JSON.parse(result.stdout);
        for (const target of trivyOutput.Results || []) {
          for (const vuln of target.Vulnerabilities || []) {
            const sevMap = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
            findings.push({
              title: `[Container] ${vuln.VulnerabilityID}: ${vuln.PkgName} ${vuln.InstalledVersion}`,
              severity: sevMap[vuln.Severity] || "medium",
              cvss: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score,
              scanner: "trivy",
              url: `${imageRef}#${target.Target}`,
              description: `${vuln.Title || vuln.VulnerabilityID} in ${vuln.PkgName} (installed: ${vuln.InstalledVersion}, fixed: ${vuln.FixedVersion || "not yet"})`,
              cweId: vuln.CweIDs?.[0]
            });
          }
        }
      } catch {
      }
    }
    console.log(`[CICD-CONTAINER] Image scan complete: ${findings.length} findings for ${imageRef}`);
  } catch (e) {
    console.warn(`[CICD-CONTAINER] Scan failed: ${e.message}`);
  }
  return findings;
}
async function runIacScanCicd(repoOrPath, commitSha, incrementalBranch) {
  const findings = [];
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
    const isUrl = repoOrPath.startsWith("http");
    const scanPath = isUrl ? `/tmp/iac-scan-${Date.now()}` : repoOrPath;
    if (isUrl) {
      if (incrementalBranch && commitSha) {
        const cloneCmd = `git clone --depth 50 ${repoOrPath} ${scanPath} && cd ${scanPath} && git diff --name-only origin/main...${commitSha} -- '*.tf' '*.yaml' '*.yml' '*.json' 'Dockerfile*' > /tmp/changed-iac-files.txt 2>/dev/null || true`;
        await executeRawCommandViaHttp(cloneCmd, 60);
        console.log(`[CICD-IAC] Incremental mode: scanning only changed IaC files on branch ${incrementalBranch}`);
      } else {
        const cloneCmd = commitSha ? `git clone --depth 1 ${repoOrPath} ${scanPath} && cd ${scanPath} && git checkout ${commitSha} 2>/dev/null || true` : `git clone --depth 1 ${repoOrPath} ${scanPath}`;
        await executeRawCommandViaHttp(cloneCmd, 60);
      }
    }
    const result = await executeRawCommandViaHttp(
      `checkov -d ${scanPath} --output json --compact --quiet 2>/dev/null || echo '{"results":{"failed_checks":[]}}'`,
      180
    );
    if (result.stdout) {
      try {
        const checkovOutput = JSON.parse(result.stdout);
        const failedChecks = checkovOutput.results?.failed_checks || [];
        for (const check of failedChecks) {
          const sevMap = {
            CRITICAL: "critical",
            HIGH: "high",
            MEDIUM: "medium",
            LOW: "low",
            INFO: "info"
          };
          findings.push({
            title: `[IaC] ${check.check_id}: ${check.check_result?.evaluated_keys?.[0] || check.name || check.check_id}`,
            severity: sevMap[check.severity || "MEDIUM"] || "medium",
            scanner: "checkov",
            url: `${repoOrPath}#${check.file_path || ""}:${check.file_line_range?.[0] || 0}`,
            description: `${check.name || check.check_id}. Resource: ${check.resource || "unknown"}. File: ${check.file_path || "unknown"} (line ${check.file_line_range?.[0] || "?"})`,
            cweId: check.guideline ? void 0 : void 0
          });
        }
      } catch {
      }
    }
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
            const sevMap = {
              CRITICAL: "critical",
              HIGH: "high",
              MEDIUM: "medium",
              LOW: "low"
            };
            findings.push({
              title: `[Terraform] ${r.rule_id}: ${r.rule_description || r.rule_id}`,
              severity: sevMap[r.severity || "MEDIUM"] || "medium",
              scanner: "tfsec",
              url: `${repoOrPath}#${r.location?.filename || ""}:${r.location?.start_line || 0}`,
              description: `${r.description || r.rule_description}. Resource: ${r.resource || "unknown"}. Impact: ${r.impact || "See documentation"}`,
              cweId: r.links?.[0] ? void 0 : void 0
            });
          }
        }
      } catch {
      }
    }
    if (isUrl) {
      await executeRawCommandViaHttp(`rm -rf ${scanPath}`, 10).catch(() => {
      });
    }
    console.log(`[CICD-IAC] Scan complete: ${findings.length} findings for ${repoOrPath}`);
  } catch (e) {
    console.warn(`[CICD-IAC] Scan failed: ${e.message}`);
  }
  return findings;
}
async function runSecretScanCicd(repoOrPath, commitSha) {
  const findings = [];
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
    const isUrl = repoOrPath.startsWith("http");
    const scanPath = isUrl ? `/tmp/secret-scan-${Date.now()}` : repoOrPath;
    if (isUrl) {
      const cloneCmd = commitSha ? `git clone --depth 10 ${repoOrPath} ${scanPath} && cd ${scanPath} && git checkout ${commitSha} 2>/dev/null || true` : `git clone --depth 10 ${repoOrPath} ${scanPath}`;
      await executeRawCommandViaHttp(cloneCmd, 60);
    }
    const result = await executeRawCommandViaHttp(
      `gitleaks detect --source ${scanPath} --report-format json --report-path /tmp/gitleaks-${Date.now()}.json --no-banner 2>/dev/null; cat /tmp/gitleaks-*.json 2>/dev/null || echo '[]'`,
      120
    );
    if (result.stdout) {
      try {
        const leaks = JSON.parse(result.stdout);
        for (const leak of Array.isArray(leaks) ? leaks : []) {
          findings.push({
            title: `[Secret] ${leak.Description || leak.RuleID || "Hardcoded Secret"}`,
            severity: "critical",
            cvss: 9,
            scanner: "gitleaks",
            url: `${repoOrPath}#${leak.File || ""}:${leak.StartLine || 0}`,
            description: `Secret detected: ${leak.Description || leak.RuleID}. File: ${leak.File || "unknown"} (line ${leak.StartLine || "?"}). Match: ${(leak.Match || "").substring(0, 50)}...`,
            cweId: "CWE-798"
          });
        }
      } catch {
      }
    }
    if (findings.length === 0) {
      const grepResult = await executeRawCommandViaHttp(
        `cd ${scanPath} && grep -rn --include='*.env' --include='*.yml' --include='*.yaml' --include='*.json' --include='*.tf' --include='*.tfvars' -E '(password|secret|api_key|access_key|private_key)s*[:=]s*["'][^"']{8,}' . 2>/dev/null | head -20`,
        30
      );
      if (grepResult.stdout?.trim()) {
        for (const line of grepResult.stdout.split("\n").filter(Boolean)) {
          const match = line.match(/^\.\/(.+?):(\d+):(.+)$/);
          if (match) {
            findings.push({
              title: `[Secret] Potential hardcoded credential in ${match[1]}`,
              severity: "high",
              scanner: "pattern-match",
              url: `${repoOrPath}#${match[1]}:${match[2]}`,
              description: `Potential secret found at ${match[1]}:${match[2]}. Review and rotate if confirmed.`,
              cweId: "CWE-798"
            });
          }
        }
      }
    }
    if (isUrl) {
      await executeRawCommandViaHttp(`rm -rf ${scanPath}`, 10).catch(() => {
      });
    }
    console.log(`[CICD-SECRETS] Scan complete: ${findings.length} findings for ${repoOrPath}`);
  } catch (e) {
    console.warn(`[CICD-SECRETS] Scan failed: ${e.message}`);
  }
  return findings;
}
async function compareWithBaseline(pipelineId, baselineId, currentFindings) {
  try {
    const { getDb } = await import("./db-JLHOBMS4.js");
    const { sql } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new Error("No DB connection");
    const baselineRows = await db.execute(
      sql.raw(`SELECT finding_title, finding_severity, finding_scanner, finding_url FROM cicd_scan_findings WHERE finding_run_id = ${baselineId}`)
    );
    const baselineFingerprints = new Set(
      (baselineRows.rows || baselineRows || []).map(
        (r) => `${(r.finding_title || "").toLowerCase().replace(/\[\w+\]\s*/g, "")}|${r.finding_scanner}`
      )
    );
    const currentFingerprints = new Set(
      currentFindings.map(
        (f) => `${f.title.toLowerCase().replace(/\[\w+\]\s*/g, "")}|${f.scanner}`
      )
    );
    let newCount = 0;
    for (const fp of currentFingerprints) {
      if (!baselineFingerprints.has(fp)) newCount++;
    }
    let fixedCount = 0;
    for (const fp of baselineFingerprints) {
      if (!currentFingerprints.has(fp)) fixedCount++;
    }
    const unchangedCount = currentFindings.length - newCount;
    return { newCount, fixedCount, unchangedCount };
  } catch (e) {
    console.warn(`[CICD-BASELINE] Comparison failed: ${e.message}`);
    return { newCount: currentFindings.length, fixedCount: 0, unchangedCount: 0 };
  }
}
async function generateSbom(imageRef) {
  const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
  const { doStoragePut } = await import("./do-storage-7IGBORB7.js");
  const result = await executeRawCommandViaHttp(
    `syft ${imageRef} -o cyclonedx-json 2>/dev/null || trivy image --format cyclonedx ${imageRef} 2>/dev/null || echo '{"components":[]}'`,
    180
  );
  let packageCount = 0;
  let sbomJson = "{}";
  if (result.stdout) {
    try {
      const parsed = JSON.parse(result.stdout);
      packageCount = (parsed.components || []).length;
      sbomJson = result.stdout;
    } catch {
      sbomJson = result.stdout;
    }
  }
  const timestamp = Date.now();
  const safeRef = imageRef.replace(/[^a-zA-Z0-9.-]/g, "_");
  const key = `cicd-sbom/${safeRef}-${timestamp}.json`;
  const { url } = await doStoragePut(key, Buffer.from(sbomJson), "application/json");
  return { url, packageCount, format: "cyclonedx" };
}
async function runProwlerCicd(provider, creds, services, compliance) {
  const findings = [];
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api-5H2UCULX.js");
    let cmd = `prowler ${provider} -M json-ocsf --no-banner`;
    if (provider === "aws" && creds) {
      cmd = `AWS_ACCESS_KEY_ID='${creds.accessKeyId}' AWS_SECRET_ACCESS_KEY='${creds.secretAccessKey}' ${creds.sessionToken ? `AWS_SESSION_TOKEN='${creds.sessionToken}' ` : ""}AWS_DEFAULT_REGION='${creds.region || "us-east-1"}' ${cmd}`;
      if (creds.roleArn) cmd += ` -R ${creds.roleArn}`;
    }
    if (services?.length) cmd += ` --services ${services.join(" ")}`;
    if (compliance) cmd += ` --compliance ${compliance}`;
    const result = await executeRawCommandViaHttp(cmd, 600);
    if (result.stdout) {
      for (const line of result.stdout.split("\n").filter(Boolean)) {
        try {
          const obj = JSON.parse(line);
          if ((obj.Status || obj.status || "").toUpperCase() === "FAIL") {
            const sev = (obj.Severity || obj.severity || "medium").toLowerCase();
            findings.push({
              title: `[Prowler] ${obj.CheckTitle || obj.check_title || obj.CheckID || "Unknown"}`,
              severity: ["critical", "high", "medium", "low"].includes(sev) ? sev : "medium",
              scanner: "prowler",
              url: `${provider}://${obj.ResourceArn || obj.ResourceId || obj.CheckID || "unknown"}`,
              description: `${obj.StatusExtended || obj.Description || ""}. Service: ${obj.ServiceName || "unknown"}. Region: ${obj.Region || "global"}. Remediation: ${obj.Remediation?.Recommendation?.Text || "Review configuration"}`,
              cweId: obj.CheckID ? `PROWLER-${obj.CheckID}` : void 0
            });
          }
        } catch {
        }
      }
    }
    console.log(`[CICD-PROWLER] ${provider} scan: ${findings.length} findings`);
  } catch (e) {
    console.warn(`[CICD-PROWLER] Scan failed: ${e.message}`);
  }
  return findings;
}
async function discoverContainerImages(registryType, registryAuth, namespace) {
  const images = [];
  try {
    const { listRepositories } = await import("./container-registry-service-POF3APR7.js");
    const repos = await listRepositories(
      registryType,
      { url: registryAuth.url || "", username: registryAuth.username || "", password: registryAuth.password || "", region: registryAuth.region },
      { limit: 50, namespace }
    );
    for (const repo of repos) {
      const tag = "latest";
      const fullRef = registryAuth.url ? `${registryAuth.url.replace(/^https?:\/\//, "")}/${repo.name}:${tag}` : `${repo.name}:${tag}`;
      images.push({
        name: repo.name,
        tag,
        fullRef,
        lastUpdated: repo.lastUpdated || repo.last_updated
      });
    }
    console.log(`[CICD-REGISTRY] Discovered ${images.length} images from ${registryType}`);
  } catch (e) {
    console.warn(`[CICD-REGISTRY] Discovery failed: ${e.message}`);
  }
  return images;
}
async function enumerateCloudIam(provider, creds) {
  const findings = [];
  try {
    const { IAM_MISCONFIG_CHECKS, analyzeCloudProvider } = await import("./cloud-attack-paths-LPWJQ5FI.js");
    const analysis = analyzeCloudProvider(provider, {});
    for (const misconfig of analysis.misconfigurations) {
      findings.push({
        title: `[IAM] ${misconfig.description}`,
        severity: misconfig.severity,
        scanner: "iam-enumerator",
        url: `${provider}://iam/${misconfig.type}`,
        description: `Resource: ${misconfig.resource}. Current: ${misconfig.currentValue}. Expected: ${misconfig.expectedValue}`
      });
    }
    for (const attack of analysis.attackPaths) {
      findings.push({
        title: `[Attack Path] ${attack.name}`,
        severity: attack.severity,
        scanner: "cloud-attack-paths",
        url: `${provider}://attack-path/${attack.id}`,
        description: `${attack.description}. MITRE: ${attack.mitreTechnique}. Risk Score: ${attack.riskScore}`
      });
    }
    console.log(`[CICD-IAM] ${provider} enumeration: ${findings.length} findings`);
  } catch (e) {
    console.warn(`[CICD-IAM] Enumeration failed: ${e.message}`);
  }
  return findings;
}
function verifyGitHubWebhook(payload, signature, secret) {
  const expected = `sha256=${crypto.createHmac("sha256", secret).update(payload).digest("hex")}`;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
function generateWebhookSecret() {
  return `ac3_whsec_${crypto.randomBytes(24).toString("hex")}`;
}
function generateWebhookUrl(pipelineId) {
  const baseUrl = process.env.VITE_APP_URL || process.env.RAILWAY_PUBLIC_DOMAIN || "";
  return `${baseUrl}/api/cicd/webhook/${pipelineId}`;
}
async function callbackGitHubActions(result, githubToken, owner, repo, commitSha) {
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
        result.reportUrl ? `[View Full Report](${result.reportUrl})` : ""
      ].join("\n"),
      text: result.findings.slice(0, 50).map(
        (f) => `### ${f.severity.toUpperCase()}: ${f.title}
- URL: ${f.url}
- Scanner: ${f.scanner}
${f.cweId ? `- CWE: ${f.cweId}` : ""}
- ${f.description.substring(0, 200)}`
      ).join("\n\n")
    }
  };
  await fetch(`https://api.github.com/repos/${owner}/${repo}/check-runs`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify(body)
  });
}
async function callbackCodePipeline(result, creds, jobId) {
  const { CodePipelineClient, PutJobSuccessResultCommand, PutJobFailureResultCommand } = await import("@aws-sdk/client-codepipeline");
  const client = new CodePipelineClient({
    region: creds.region || "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken
    }
  });
  if (result.status === "passed") {
    await client.send(new PutJobSuccessResultCommand({
      jobId,
      executionDetails: {
        summary: `AC3 Security Scan passed: ${result.totalFindings} findings, max CVSS ${result.maxCvss}`,
        percentComplete: 100
      }
    }));
  } else {
    await client.send(new PutJobFailureResultCommand({
      jobId,
      failureDetails: {
        type: "JobFailed",
        message: `AC3 Security Scan failed: ${result.criticalCount} critical, ${result.highCount} high findings (max CVSS ${result.maxCvss})`
      }
    }));
  }
}
function generateGitHubActionsYaml(webhookUrl, webhookSecret) {
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
function generateCodePipelineYaml() {
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
function generateGitLabCiYaml(webhookUrl) {
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
      PAYLOAD='{"event":"deployment","target_url":"https://staging.yourapp.com","commit_sha":"'$CI_COMMIT_SHA'","branch":"'$CI_COMMIT_REF_NAME'","repository":"'$CI_PROJECT_PATH'"}'
      SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$AC3_WEBHOOK_SECRET" | awk '{print $2}')
      curl -X POST "${webhookUrl}" \\
        -H "Content-Type: application/json" \\
        -H "X-Webhook-Signature: sha256=$SIGNATURE" \\
        -d "$PAYLOAD"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
`;
}
function generateJenkinsfileYaml(webhookUrl) {
  return `// AC3 Security Scan - Jenkins Pipeline Integration
// Add this as a stage in your Jenkinsfile

pipeline {
    agent any

    environment {
        AC3_WEBHOOK_URL = '${webhookUrl}'
        AC3_WEBHOOK_SECRET = credentials('ac3-webhook-secret')
    }

    stages {
        stage('Deploy to Staging') {
            steps {
                echo 'Deploy to staging environment'
                // Your deployment steps here
            }
        }

        stage('AC3 Security Scan') {
            steps {
                script {
                    def payload = """{"event":"deployment","target_url":"https://staging.yourapp.com","commit_sha":"\${env.GIT_COMMIT}","branch":"\${env.GIT_BRANCH}","repository":"\${env.JOB_NAME}"}"""
                    def signature = sh(
                        script: "echo -n '\${payload}' | openssl dgst -sha256 -hmac '\${AC3_WEBHOOK_SECRET}' | awk '{print \\$2}'",
                        returnStdout: true
                    ).trim()

                    httpRequest(
                        url: "\${AC3_WEBHOOK_URL}",
                        httpMode: 'POST',
                        contentType: 'APPLICATION_JSON',
                        customHeaders: [
                            [name: 'X-Webhook-Signature', value: "sha256=\${signature}"]
                        ],
                        requestBody: payload
                    )
                }
            }
        }
    }

    post {
        always {
            echo 'AC3 scan triggered. Results will be posted back.'
        }
    }
}
`;
}
function generateAzureDevOpsYaml(webhookUrl) {
  return `# AC3 Security Scan - Azure DevOps Pipeline Integration
# Add this to your azure-pipelines.yml

trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

stages:
  - stage: Deploy
    displayName: 'Deploy to Staging'
    jobs:
      - job: DeployStaging
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: echo 'Deploy to staging'
            displayName: 'Deploy'

  - stage: SecurityScan
    displayName: 'AC3 Security Scan'
    dependsOn: Deploy
    jobs:
      - job: TriggerAC3Scan
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: Bash@3
            displayName: 'Trigger AC3 Security Scan'
            inputs:
              targetType: 'inline'
              script: |
                PAYLOAD='{"event":"deployment","target_url":"https://staging.yourapp.com","commit_sha":"'$(Build.SourceVersion)'","branch":"'$(Build.SourceBranchName)'","repository":"'$(Build.Repository.Name)'"}'
                SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$(AC3_WEBHOOK_SECRET)" | awk '{print $2}')
                curl -X POST "${webhookUrl}" \\
                  -H "Content-Type: application/json" \\
                  -H "X-Webhook-Signature: sha256=$SIGNATURE" \\
                  -d "$PAYLOAD"
            env:
              AC3_WEBHOOK_SECRET: $(AC3_WEBHOOK_SECRET)

# Setup:
# 1. Add AC3_WEBHOOK_SECRET as a secret variable in your pipeline
# 2. Replace staging URL with your actual staging environment URL
# 3. Ensure the pipeline has permission to access the secret variable
`;
}
export {
  assumeRole,
  callbackCodePipeline,
  callbackGitHubActions,
  compareWithBaseline,
  discoverContainerImages,
  discoverEnvironments,
  enumerateCloudIam,
  executeCicdScan,
  generateAzureDevOpsYaml,
  generateCodePipelineYaml,
  generateGitHubActionsYaml,
  generateGitLabCiYaml,
  generateJenkinsfileYaml,
  generateSbom,
  generateWebhookSecret,
  generateWebhookUrl,
  runProwlerCicd,
  scanServerPreFlight,
  validateCredentials,
  validateTargetUrl,
  verifyGitHubWebhook
};
