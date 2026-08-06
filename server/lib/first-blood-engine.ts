/**
 * First Blood Engine — Parallel Fast-Path Pipeline
 * ==================================================
 * Runs 4 parallel attack vectors simultaneously to achieve "first blood"
 * (initial compromise evidence) in minutes rather than hours:
 *
 *   Lane 1: Nuclei Critical/High — top 100 templates for known CVEs
 *   Lane 2: KEV Exploit Matching — CISA KEV cross-reference with auto-exploit
 *   Lane 3: Credential Spray — default creds, leaked creds, common passwords
 *   Lane 4: Cloud Misconfig — S3 buckets, open APIs, IAM misconfig, metadata
 *
 * All lanes run in parallel. First finding that achieves access = "first blood".
 * Results are streamed back in priority order (critical first).
 *
 * Competitive positioning: Matches Horizon3's "minutes to first result" speed
 * while using AC3's deeper toolchain for validation.
 *
 * @author Harrison Cook — AceofCloud
 */
import { startNucleiScan, type NucleiFinding } from "./nuclei-engine";
import { fetchKevCatalog, matchTechnologiesAgainstKev, type KevMatch } from "./kev-service";
import { invokeLLM } from "../_core/llm";
import { ENV } from "../_core/env";
import axios from "axios";

// ─── Types ──────────────────────────────────────────────────────────────────

export type FirstBloodLane = "nuclei_critical" | "kev_exploit" | "credential_spray" | "cloud_misconfig";

export type FirstBloodFinding = {
  lane: FirstBloodLane;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  evidence: string;
  target: string;
  cveId?: string;
  technique?: string; // MITRE ATT&CK
  exploitable: boolean;
  accessAchieved: boolean;
  timestamp: number;
};

export type LaneStatus = {
  lane: FirstBloodLane;
  status: "pending" | "running" | "complete" | "error";
  startedAt?: number;
  completedAt?: number;
  findingsCount: number;
  accessAchieved: boolean;
  error?: string;
};

export type FirstBloodResult = {
  firstBloodAchieved: boolean;
  firstBloodLane?: FirstBloodLane;
  firstBloodTimestamp?: number;
  timeToFirstBloodMs?: number;
  totalFindings: number;
  criticalFindings: number;
  lanes: LaneStatus[];
  findings: FirstBloodFinding[];
  summary: string;
};

export type FirstBloodConfig = {
  targets: string[]; // domains, IPs, URLs
  technologies?: string[]; // detected tech stack
  credentials?: { username: string; password: string }[]; // known/leaked creds
  cloudProvider?: "aws" | "azure" | "gcp";
  maxDurationMs?: number; // timeout (default 5 min)
  engagementId?: number;
};

// ─── Lane Implementations ───────────────────────────────────────────────────

/**
 * Lane 1: Nuclei Critical — run top critical/high severity templates
 */
async function runNucleiCriticalLane(config: FirstBloodConfig): Promise<FirstBloodFinding[]> {
  const findings: FirstBloodFinding[] = [];

  const targets = config.targets.map(t => ({
    host: t.replace(/^https?:\/\//, ""),
    port: t.includes(":443") || t.startsWith("https") ? 443 : 80,
    service: "http",
  }));

  const scanResult = await startNucleiScan({
    targets,
    severity: ["critical", "high"],
    templateCategories: ["cves", "vulnerabilities", "misconfiguration"],
    engagementId: config.engagementId,
    rateLimit: 150,
    timeout: 120000,
  });

  for (const f of scanResult.findings || []) {
    findings.push({
      lane: "nuclei_critical",
      severity: f.severity as any || "high",
      title: f.name || f.templateId || "Unknown Vulnerability",
      description: f.description || `Nuclei template match: ${f.templateId}`,
      evidence: f.matchedAt || f.host || "",
      target: f.host || config.targets[0],
      cveId: f.cveId,
      technique: mapCveToTechnique(f.cveId),
      exploitable: f.severity === "critical",
      accessAchieved: isAccessVuln(f),
      timestamp: Date.now(),
    });
  }

  return findings;
}

/**
 * Lane 2: KEV Exploit Matching — cross-reference with CISA Known Exploited Vulnerabilities
 */
async function runKevExploitLane(config: FirstBloodConfig): Promise<FirstBloodFinding[]> {
  const findings: FirstBloodFinding[] = [];

  try {
    const kevCatalog = await fetchKevCatalog();
    if (!kevCatalog || !kevCatalog.vulnerabilities) return findings;

    // Match technologies against KEV
    const techVersions: Record<string, string> = {};
    for (const tech of config.technologies || []) {
      techVersions[tech] = "unknown";
    }

    const kevMatches = matchTechnologiesAgainstKev(techVersions, kevCatalog);

    for (const match of kevMatches) {
      findings.push({
        lane: "kev_exploit",
        severity: "critical",
        title: `KEV: ${match.cveId} — ${match.vulnerabilityName || "Known Exploited Vulnerability"}`,
        description: `CISA KEV match: ${match.shortDescription || match.vulnerabilityName}. Known to be actively exploited in the wild.`,
        evidence: `Technology: ${match.product || "unknown"}, Vendor: ${match.vendorProject || "unknown"}`,
        target: config.targets[0],
        cveId: match.cveId,
        technique: "T1190", // Exploit Public-Facing Application
        exploitable: true,
        accessAchieved: true, // KEV = known exploited = access likely achievable
        timestamp: Date.now(),
      });
    }
  } catch (err) {
    // KEV service unavailable — skip
  }

  return findings;
}

/**
 * Lane 3: Credential Spray — test default credentials and common passwords
 */
async function runCredentialSprayLane(config: FirstBloodConfig): Promise<FirstBloodFinding[]> {
  const findings: FirstBloodFinding[] = [];

  // Default credential pairs to test
  const defaultCreds = [
    { username: "admin", password: "admin" },
    { username: "admin", password: "password" },
    { username: "admin", password: "admin123" },
    { username: "root", password: "root" },
    { username: "root", password: "toor" },
    { username: "administrator", password: "Password1" },
    { username: "test", password: "test" },
    { username: "user", password: "user" },
    ...(config.credentials || []),
  ];

  // Common login endpoints to test
  const loginEndpoints = [
    "/admin", "/login", "/wp-admin", "/wp-login.php",
    "/administrator", "/admin/login", "/api/login",
    "/auth/login", "/user/login", "/console",
    "/phpmyadmin", "/adminer", "/grafana/login",
    "/jenkins/login", "/gitlab/users/sign_in",
  ];

  for (const target of config.targets) {
    const baseUrl = target.startsWith("http") ? target : `https://${target}`;

    for (const endpoint of loginEndpoints) {
      try {
        const response = await axios.get(`${baseUrl}${endpoint}`, {
          timeout: 5000,
          maxRedirects: 2,
          validateStatus: () => true,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-CredSpray/1.0)" },
        });

        // Check if login page exists (200 or 401/403 with form)
        if (response.status === 200 || response.status === 401 || response.status === 403) {
          const body = typeof response.data === "string" ? response.data.toLowerCase() : "";
          const hasLoginForm = body.includes("password") && (body.includes("username") || body.includes("email") || body.includes("login"));

          if (hasLoginForm || response.status === 401) {
            // Test default credentials
            for (const cred of defaultCreds.slice(0, 5)) {
              try {
                const loginResponse = await axios.post(`${baseUrl}${endpoint}`, {
                  username: cred.username,
                  password: cred.password,
                  email: cred.username,
                }, {
                  timeout: 5000,
                  maxRedirects: 0,
                  validateStatus: () => true,
                  headers: {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (compatible; AC3-CredSpray/1.0)",
                  },
                });

                // Check for successful auth indicators
                const isSuccess = loginResponse.status === 200 || loginResponse.status === 302;
                const hasToken = loginResponse.headers["set-cookie"]?.some((c: string) =>
                  c.includes("session") || c.includes("token") || c.includes("auth")
                );
                const bodyStr = typeof loginResponse.data === "string" ? loginResponse.data : JSON.stringify(loginResponse.data || "");
                const hasSuccessBody = bodyStr.includes("token") || bodyStr.includes("dashboard") || bodyStr.includes("welcome");

                if (isSuccess && (hasToken || hasSuccessBody)) {
                  findings.push({
                    lane: "credential_spray",
                    severity: "critical",
                    title: `Default Credentials: ${cred.username}:${cred.password} on ${endpoint}`,
                    description: `Successfully authenticated with default credentials at ${baseUrl}${endpoint}`,
                    evidence: `HTTP ${loginResponse.status}, Set-Cookie: ${loginResponse.headers["set-cookie"]?.join("; ") || "N/A"}`,
                    target: `${baseUrl}${endpoint}`,
                    technique: "T1078.001", // Valid Accounts: Default Accounts
                    exploitable: true,
                    accessAchieved: true,
                    timestamp: Date.now(),
                  });
                  break; // Found valid creds, move to next endpoint
                }
              } catch {
                // Login attempt failed, continue
              }
            }
          }
        }
      } catch {
        // Endpoint unreachable, continue
      }
    }
  }

  return findings;
}

/**
 * Lane 4: Cloud Misconfiguration — check for exposed cloud resources
 */
async function runCloudMisconfigLane(config: FirstBloodConfig): Promise<FirstBloodFinding[]> {
  const findings: FirstBloodFinding[] = [];

  for (const target of config.targets) {
    const domain = target.replace(/^https?:\/\//, "").split("/")[0];

    // Check for exposed S3 buckets
    const bucketNames = [
      domain.replace(/\./g, "-"),
      domain.split(".")[0],
      `${domain.split(".")[0]}-backup`,
      `${domain.split(".")[0]}-dev`,
      `${domain.split(".")[0]}-staging`,
      `${domain.split(".")[0]}-assets`,
      `${domain.split(".")[0]}-data`,
    ];

    for (const bucket of bucketNames) {
      try {
        const response = await axios.get(`https://${bucket}.s3.amazonaws.com`, {
          timeout: 5000,
          validateStatus: () => true,
        });

        if (response.status === 200 && typeof response.data === "string" && response.data.includes("ListBucketResult")) {
          findings.push({
            lane: "cloud_misconfig",
            severity: "high",
            title: `Open S3 Bucket: ${bucket}`,
            description: `S3 bucket "${bucket}" allows unauthenticated listing. May contain sensitive data.`,
            evidence: `HTTP 200 on https://${bucket}.s3.amazonaws.com with ListBucketResult`,
            target: `https://${bucket}.s3.amazonaws.com`,
            technique: "T1530", // Data from Cloud Storage Object
            exploitable: true,
            accessAchieved: true,
            timestamp: Date.now(),
          });
        }
      } catch {
        // Bucket doesn't exist or is private
      }
    }

    // Check for exposed metadata endpoints (SSRF indicator)
    try {
      const metadataUrl = `http://${domain}/latest/meta-data/`;
      const response = await axios.get(metadataUrl, {
        timeout: 3000,
        validateStatus: () => true,
      });
      if (response.status === 200 && typeof response.data === "string" && response.data.includes("ami-id")) {
        findings.push({
          lane: "cloud_misconfig",
          severity: "critical",
          title: `Exposed Cloud Metadata: ${domain}`,
          description: `Cloud instance metadata endpoint is accessible. SSRF to credential theft possible.`,
          evidence: `HTTP 200 on ${metadataUrl}`,
          target: metadataUrl,
          technique: "T1552.005", // Cloud Instance Metadata API
          exploitable: true,
          accessAchieved: true,
          timestamp: Date.now(),
        });
      }
    } catch {
      // Not accessible
    }

    // Check for exposed .env files
    const sensitiveFiles = ["/.env", "/.git/config", "/wp-config.php.bak", "/config.json", "/.aws/credentials"];
    for (const file of sensitiveFiles) {
      try {
        const baseUrl = target.startsWith("http") ? target : `https://${target}`;
        const response = await axios.get(`${baseUrl}${file}`, {
          timeout: 3000,
          validateStatus: () => true,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-CloudCheck/1.0)" },
        });
        if (response.status === 200 && typeof response.data === "string") {
          const body = response.data.toLowerCase();
          if (body.includes("password") || body.includes("secret") || body.includes("api_key") || body.includes("access_key")) {
            findings.push({
              lane: "cloud_misconfig",
              severity: "critical",
              title: `Exposed Sensitive File: ${file}`,
              description: `Sensitive configuration file accessible at ${baseUrl}${file}. Contains credentials or secrets.`,
              evidence: `HTTP 200, content contains credential indicators`,
              target: `${baseUrl}${file}`,
              technique: "T1552.001", // Credentials In Files
              exploitable: true,
              accessAchieved: true,
              timestamp: Date.now(),
            });
          }
        }
      } catch {
        // Not accessible
      }
    }
  }

  return findings;
}

// ─── Main Orchestrator ──────────────────────────────────────────────────────

/**
 * Execute all 4 lanes in parallel and return prioritized findings
 */
export async function executeFirstBlood(config: FirstBloodConfig): Promise<FirstBloodResult> {
  const startTime = Date.now();
  const maxDuration = config.maxDurationMs || 300000; // 5 min default

  const lanes: LaneStatus[] = [
    { lane: "nuclei_critical", status: "pending", findingsCount: 0, accessAchieved: false },
    { lane: "kev_exploit", status: "pending", findingsCount: 0, accessAchieved: false },
    { lane: "credential_spray", status: "pending", findingsCount: 0, accessAchieved: false },
    { lane: "cloud_misconfig", status: "pending", findingsCount: 0, accessAchieved: false },
  ];

  // Run all lanes in parallel with timeout
  const lanePromises = [
    runLaneWithTimeout("nuclei_critical", () => runNucleiCriticalLane(config), maxDuration),
    runLaneWithTimeout("kev_exploit", () => runKevExploitLane(config), maxDuration),
    runLaneWithTimeout("credential_spray", () => runCredentialSprayLane(config), maxDuration),
    runLaneWithTimeout("cloud_misconfig", () => runCloudMisconfigLane(config), maxDuration),
  ];

  const results = await Promise.allSettled(lanePromises);

  // Collect all findings
  const allFindings: FirstBloodFinding[] = [];
  const laneNames: FirstBloodLane[] = ["nuclei_critical", "kev_exploit", "credential_spray", "cloud_misconfig"];

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const laneName = laneNames[i];

    if (result.status === "fulfilled") {
      const laneFindings = result.value;
      allFindings.push(...laneFindings);
      lanes[i] = {
        lane: laneName,
        status: "complete",
        startedAt: startTime,
        completedAt: Date.now(),
        findingsCount: laneFindings.length,
        accessAchieved: laneFindings.some(f => f.accessAchieved),
      };
    } else {
      lanes[i] = {
        lane: laneName,
        status: "error",
        startedAt: startTime,
        completedAt: Date.now(),
        findingsCount: 0,
        accessAchieved: false,
        error: result.reason?.message || "Unknown error",
      };
    }
  }

  // Sort findings: critical first, then by access achieved, then by timestamp
  allFindings.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (a.accessAchieved !== b.accessAchieved) return a.accessAchieved ? -1 : 1;
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    return a.timestamp - b.timestamp;
  });

  // Determine first blood
  const firstBloodFinding = allFindings.find(f => f.accessAchieved);
  const firstBloodAchieved = !!firstBloodFinding;

  // Generate summary
  const criticalCount = allFindings.filter(f => f.severity === "critical").length;
  const summary = firstBloodAchieved
    ? `FIRST BLOOD achieved via ${firstBloodFinding!.lane} in ${((firstBloodFinding!.timestamp - startTime) / 1000).toFixed(1)}s: ${firstBloodFinding!.title}`
    : `No initial access achieved. ${allFindings.length} findings across ${lanes.filter(l => l.status === "complete").length} lanes.`;

  return {
    firstBloodAchieved,
    firstBloodLane: firstBloodFinding?.lane,
    firstBloodTimestamp: firstBloodFinding?.timestamp,
    timeToFirstBloodMs: firstBloodFinding ? firstBloodFinding.timestamp - startTime : undefined,
    totalFindings: allFindings.length,
    criticalFindings: criticalCount,
    lanes,
    findings: allFindings,
    summary,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function runLaneWithTimeout<T>(
  laneName: string,
  fn: () => Promise<T[]>,
  timeoutMs: number
): Promise<T[]> {
  return Promise.race([
    fn(),
    new Promise<T[]>((_, reject) =>
      setTimeout(() => reject(new Error(`Lane ${laneName} timed out after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}

function isAccessVuln(finding: any): boolean {
  const accessIndicators = ["rce", "remote code", "command injection", "sql injection", "auth bypass", "ssrf", "lfi", "rfi"];
  const name = (finding.name || finding.templateId || "").toLowerCase();
  const desc = (finding.description || "").toLowerCase();
  return accessIndicators.some(i => name.includes(i) || desc.includes(i));
}

function mapCveToTechnique(cveId?: string): string | undefined {
  if (!cveId) return undefined;
  // Common CVE-to-technique mappings
  return "T1190"; // Default: Exploit Public-Facing Application
}
