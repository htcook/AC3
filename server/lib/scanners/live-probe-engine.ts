/**
 * FAISS / LangChain / RAG Live Probe Engine
 * ==========================================
 * Active HTTP probes that detect RAG endpoints, exposed FAISS indexes,
 * LangChain agent tool enumeration, and vector DB interfaces in real-time
 * during the scan pipeline.
 *
 * Unlike the static scanner modules, this engine sends actual HTTP requests
 * to discover live attack surface. All probes are non-destructive (read-only)
 * and respect RoE scope constraints.
 *
 * @author Harrison Cook — AceofCloud
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ProbeTarget {
  baseUrl: string;
  hostname: string;
  port?: number;
}

export interface ProbeResult {
  probeType: string;
  target: string;
  path: string;
  status: "found" | "not_found" | "error" | "auth_required";
  statusCode?: number;
  confidence: number;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  finding?: string;
  recommendation?: string;
}

export interface LiveProbeReport {
  target: string;
  probesRun: number;
  probesSuccessful: number;
  findings: ProbeResult[];
  ragEndpoints: string[];
  faissExposures: string[];
  langchainEndpoints: string[];
  firebaseExposures: string[];
  jupyterExposures: string[];
  totalDurationMs: number;
}

// ─── Probe Definitions ──────────────────────────────────────────────────────

/** FAISS index file exposure probes */
export const FAISS_PROBE_PATHS = [
  // Direct file access
  "/index.faiss",
  "/faiss_index/index.faiss",
  "/data/index.faiss",
  "/models/index.faiss",
  "/vectorstore/index.faiss",
  "/db/index.faiss",
  "/vector_db/index.faiss",
  "/embeddings/index.faiss",
  // Pickle files (often paired with FAISS)
  "/index.pkl",
  "/faiss_index/index.pkl",
  "/data/index.pkl",
  "/vectorstore/index.pkl",
  "/embeddings/index.pkl",
  // Common RAG data directories
  "/data/embeddings.npy",
  "/data/vectors.npy",
  "/chroma/",
  "/chromadb/",
  "/weaviate/",
  "/qdrant/",
  // S3-style paths
  "/.env",
  "/config.json",
  "/config.yaml",
  "/config.yml",
];

/** LangChain/LangServe endpoint probes */
export const LANGCHAIN_PROBE_PATHS = [
  // LangServe standard endpoints
  "/invoke",
  "/stream",
  "/batch",
  "/playground",
  "/playground/",
  "/input_schema",
  "/output_schema",
  "/config_schema",
  // Common LangChain API patterns
  "/api/invoke",
  "/api/stream",
  "/api/chat",
  "/api/query",
  "/api/ask",
  "/api/rag",
  "/api/search",
  "/api/completion",
  "/api/completions",
  // Agent-specific endpoints
  "/agent/invoke",
  "/agent/run",
  "/agent/tools",
  "/agent/memory",
  // Chain endpoints
  "/chain/invoke",
  "/chain/run",
  "/retrieval/query",
  "/retrieval/search",
  // OpenAPI/docs
  "/docs",
  "/openapi.json",
  "/redoc",
];

/** RAG-specific endpoint probes */
export const RAG_PROBE_PATHS = [
  "/api/documents",
  "/api/documents/upload",
  "/api/documents/search",
  "/api/embeddings",
  "/api/embeddings/search",
  "/api/vectors/search",
  "/api/similarity",
  "/api/semantic-search",
  "/upload",
  "/ingest",
  "/index",
];

/** Firebase exposure probes */
export const FIREBASE_PROBE_PATHS = [
  "/__/firebase/init.json",
  "/__/firebase/init.js",
  "/.well-known/firebase",
  "/firebase-config.json",
  "/firebase-config.js",
];

/** Jupyter exposure probes */
export const JUPYTER_PROBE_PATHS = [
  "/api/kernels",
  "/api/kernelspecs",
  "/api/contents",
  "/api/sessions",
  "/api/terminals",
  "/api/status",
  "/api",
  "/hub/api",
  "/hub/api/users",
  "/user-redirect/",
  "/tree",
  "/lab",
  "/notebooks",
];

// ─── Probe Execution ────────────────────────────────────────────────────────

/**
 * Build probe configurations for a target.
 * Returns an array of probe specs that can be executed.
 */
export function buildProbeSpecs(target: ProbeTarget): Array<{
  category: string;
  path: string;
  method: "GET" | "POST" | "OPTIONS";
  body?: string;
  headers?: Record<string, string>;
  expectedIndicators: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
}> {
  const specs: Array<{
    category: string;
    path: string;
    method: "GET" | "POST" | "OPTIONS";
    body?: string;
    headers?: Record<string, string>;
    expectedIndicators: string[];
    severity: "critical" | "high" | "medium" | "low" | "info";
  }> = [];

  // FAISS probes
  for (const path of FAISS_PROBE_PATHS) {
    specs.push({
      category: "faiss",
      path,
      method: "GET",
      expectedIndicators: [
        "application/octet-stream",
        "faiss",
        "pickle",
        "numpy",
        ".npy",
      ],
      severity: path.endsWith(".pkl") ? "critical" : path.endsWith(".faiss") ? "high" : "medium",
    });
  }

  // LangChain probes
  for (const path of LANGCHAIN_PROBE_PATHS) {
    if (path === "/invoke" || path === "/api/invoke" || path === "/agent/invoke" || path === "/chain/invoke") {
      // POST probe with test payload
      specs.push({
        category: "langchain",
        path,
        method: "POST",
        body: JSON.stringify({ input: "test" }),
        headers: { "Content-Type": "application/json" },
        expectedIndicators: [
          "output",
          "result",
          "response",
          "langchain",
          "agent",
          "chain",
        ],
        severity: "high",
      });
    } else if (path === "/agent/tools" || path === "/agent/memory") {
      specs.push({
        category: "langchain",
        path,
        method: "GET",
        expectedIndicators: [
          "tools",
          "memory",
          "ShellTool",
          "PythonREPL",
          "langchain",
        ],
        severity: "critical",
      });
    } else {
      specs.push({
        category: "langchain",
        path,
        method: "GET",
        expectedIndicators: [
          "langserve",
          "langchain",
          "invoke",
          "schema",
          "playground",
          "openapi",
        ],
        severity: path.includes("schema") ? "medium" : "high",
      });
    }
  }

  // RAG probes
  for (const path of RAG_PROBE_PATHS) {
    specs.push({
      category: "rag",
      path,
      method: path.includes("search") || path.includes("query") ? "POST" : "GET",
      body: path.includes("search") || path.includes("query")
        ? JSON.stringify({ query: "test", q: "test" })
        : undefined,
      headers: path.includes("search") || path.includes("query")
        ? { "Content-Type": "application/json" }
        : undefined,
      expectedIndicators: [
        "documents",
        "embeddings",
        "vectors",
        "results",
        "matches",
        "similarity",
      ],
      severity: path.includes("upload") || path.includes("ingest") ? "critical" : "high",
    });
  }

  // Firebase probes
  for (const path of FIREBASE_PROBE_PATHS) {
    specs.push({
      category: "firebase",
      path,
      method: "GET",
      expectedIndicators: [
        "apiKey",
        "projectId",
        "authDomain",
        "storageBucket",
        "messagingSenderId",
        "firebase",
      ],
      severity: "high",
    });
  }

  // Jupyter probes
  for (const path of JUPYTER_PROBE_PATHS) {
    specs.push({
      category: "jupyter",
      path,
      method: "GET",
      expectedIndicators: [
        "kernel",
        "notebook",
        "jupyter",
        "session",
        "terminal",
        "contents",
      ],
      severity: path.includes("kernels") || path.includes("terminals") ? "critical" : "high",
    });
  }

  return specs;
}

/**
 * Analyze a probe response to determine if it indicates a finding.
 */
export function analyzeProbeResponse(
  probeCategory: string,
  path: string,
  statusCode: number,
  responseBody: string,
  responseHeaders: Record<string, string>,
  expectedIndicators: string[],
  severity: "critical" | "high" | "medium" | "low" | "info",
): ProbeResult | null {
  // Skip clear 404s, 403s without interesting info, and 5xx errors
  if (statusCode === 404) return null;
  if (statusCode >= 500) return null;

  const bodyLower = responseBody.toLowerCase();
  const matchedIndicators = expectedIndicators.filter(ind =>
    bodyLower.includes(ind.toLowerCase())
  );

  // 200 with matching indicators = confirmed finding
  if (statusCode === 200 && matchedIndicators.length > 0) {
    return buildFinding(probeCategory, path, statusCode, "found", matchedIndicators, severity, responseBody);
  }

  // 200 with binary content (potential file download)
  const contentType = responseHeaders["content-type"] || "";
  if (statusCode === 200 && (
    contentType.includes("octet-stream") ||
    contentType.includes("application/x-pickle") ||
    contentType.includes("application/x-numpy")
  )) {
    return buildFinding(probeCategory, path, statusCode, "found",
      [`Binary content: ${contentType}`], "critical", `Binary file download: ${contentType}`);
  }

  // 401/403 = exists but requires auth
  if (statusCode === 401 || statusCode === 403) {
    if (matchedIndicators.length > 0 || isInterestingAuthResponse(bodyLower, probeCategory)) {
      return buildFinding(probeCategory, path, statusCode, "auth_required",
        matchedIndicators.length > 0 ? matchedIndicators : ["Auth-gated endpoint exists"],
        "medium", responseBody);
    }
  }

  // 405 Method Not Allowed on POST endpoints = endpoint exists
  if (statusCode === 405 && probeCategory === "langchain") {
    return buildFinding(probeCategory, path, statusCode, "found",
      ["Method Not Allowed (endpoint exists)"], "medium", responseBody);
  }

  // 200 with JSON response containing interesting keys
  if (statusCode === 200 && contentType.includes("json")) {
    try {
      const json = JSON.parse(responseBody);
      const interestingKeys = findInterestingKeys(json, probeCategory);
      if (interestingKeys.length > 0) {
        return buildFinding(probeCategory, path, statusCode, "found",
          interestingKeys, severity, responseBody);
      }
    } catch { /* not JSON */ }
  }

  return null;
}

function buildFinding(
  category: string,
  path: string,
  statusCode: number,
  status: "found" | "auth_required",
  evidence: string[],
  severity: "critical" | "high" | "medium" | "low" | "info",
  responseBody: string,
): ProbeResult {
  const findings = FINDING_TEMPLATES[category] || {};
  const template = findings[status] || { finding: `${category} endpoint detected`, recommendation: "Review access controls" };

  return {
    probeType: category,
    target: "",
    path,
    status,
    statusCode,
    confidence: status === "found" ? 0.9 : 0.6,
    evidence: evidence.join("; "),
    severity: status === "auth_required" ? "medium" : severity,
    finding: template.finding + ` at ${path}`,
    recommendation: template.recommendation,
  };
}

function isInterestingAuthResponse(body: string, category: string): boolean {
  const categoryKeywords: Record<string, string[]> = {
    faiss: ["index", "vector", "embedding"],
    langchain: ["invoke", "chain", "agent", "unauthorized"],
    rag: ["document", "embedding", "search"],
    firebase: ["firebase", "project", "api"],
    jupyter: ["jupyter", "kernel", "notebook", "login"],
  };
  const keywords = categoryKeywords[category] || [];
  return keywords.some(kw => body.includes(kw));
}

function findInterestingKeys(obj: any, category: string): string[] {
  if (!obj || typeof obj !== "object") return [];
  const keys = Object.keys(obj);
  const interestingPatterns: Record<string, RegExp[]> = {
    faiss: [/vector/i, /embedding/i, /index/i, /dimension/i],
    langchain: [/tool/i, /agent/i, /chain/i, /memory/i, /invoke/i, /schema/i],
    rag: [/document/i, /embedding/i, /chunk/i, /retriev/i, /vector/i],
    firebase: [/apiKey/i, /projectId/i, /authDomain/i, /storageBucket/i],
    jupyter: [/kernel/i, /notebook/i, /session/i, /terminal/i],
  };
  const patterns = interestingPatterns[category] || [];
  return keys.filter(k => patterns.some(p => p.test(k))).map(k => `JSON key: ${k}`);
}

// ─── Finding Templates ──────────────────────────────────────────────────────

const FINDING_TEMPLATES: Record<string, Record<string, { finding: string; recommendation: string }>> = {
  faiss: {
    found: {
      finding: "Exposed FAISS index/pickle file",
      recommendation: "Remove public access to FAISS index files. Pickle files are especially dangerous as they allow arbitrary code execution via deserialization. Move indexes behind authentication and restrict to internal networks.",
    },
    auth_required: {
      finding: "FAISS index endpoint exists but requires authentication",
      recommendation: "Verify authentication is properly enforced. Test for auth bypass vulnerabilities and ensure pickle deserialization is not exposed even to authenticated users.",
    },
  },
  langchain: {
    found: {
      finding: "Exposed LangChain/LangServe endpoint",
      recommendation: "Restrict access to LangChain endpoints. If agent tools include ShellTool, PythonREPL, or file system access, this is a critical RCE vector. Implement input validation, rate limiting, and tool sandboxing.",
    },
    auth_required: {
      finding: "LangChain endpoint exists but requires authentication",
      recommendation: "Test for authentication bypass. Even authenticated endpoints may be vulnerable to prompt injection that causes the agent to execute dangerous tools.",
    },
  },
  rag: {
    found: {
      finding: "Exposed RAG/document endpoint",
      recommendation: "Restrict document upload/search endpoints. Unauthenticated RAG endpoints allow data poisoning (injecting malicious documents into the knowledge base) and data exfiltration (extracting sensitive documents via semantic search).",
    },
    auth_required: {
      finding: "RAG endpoint exists but requires authentication",
      recommendation: "Test for auth bypass. Even authenticated RAG endpoints may allow indirect prompt injection via poisoned documents.",
    },
  },
  firebase: {
    found: {
      finding: "Exposed Firebase configuration",
      recommendation: "Firebase config exposure reveals project ID, API key, and auth domain. While API keys alone aren't secret, combined with misconfigured Firestore rules, this enables unauthorized data access. Audit Firestore security rules immediately.",
    },
    auth_required: {
      finding: "Firebase endpoint exists but requires authentication",
      recommendation: "Test Firestore security rules for unauthenticated read/write access. Check if Firebase Auth allows anonymous sign-up that bypasses intended access controls.",
    },
  },
  jupyter: {
    found: {
      finding: "Exposed Jupyter endpoint",
      recommendation: "Jupyter kernel access = full RCE on the server. Immediately restrict access, require token/password authentication, and isolate Jupyter instances in containers with minimal privileges.",
    },
    auth_required: {
      finding: "Jupyter endpoint exists but requires authentication",
      recommendation: "Test for default/weak tokens, brute-force token enumeration, and path traversal to access notebook files without authentication.",
    },
  },
};

// ─── Report Generation ──────────────────────────────────────────────────────

/**
 * Generate a summary report from probe results.
 */
export function generateProbeReport(
  target: ProbeTarget,
  results: ProbeResult[],
  durationMs: number,
): LiveProbeReport {
  const findings = results.filter(r => r.status === "found" || r.status === "auth_required");

  return {
    target: target.baseUrl,
    probesRun: results.length + results.filter(r => r.status === "not_found" || r.status === "error").length,
    probesSuccessful: findings.length,
    findings,
    ragEndpoints: findings
      .filter(f => f.probeType === "rag")
      .map(f => f.path),
    faissExposures: findings
      .filter(f => f.probeType === "faiss")
      .map(f => f.path),
    langchainEndpoints: findings
      .filter(f => f.probeType === "langchain")
      .map(f => f.path),
    firebaseExposures: findings
      .filter(f => f.probeType === "firebase")
      .map(f => f.path),
    jupyterExposures: findings
      .filter(f => f.probeType === "jupyter")
      .map(f => f.path),
    totalDurationMs: durationMs,
  };
}

/**
 * Format probe report as a human-readable ops log entry.
 */
export function formatProbeReportForLog(report: LiveProbeReport): string {
  const lines: string[] = [
    `Live Probe Scan: ${report.target}`,
    `Probes: ${report.probesRun} run, ${report.probesSuccessful} findings (${report.totalDurationMs}ms)`,
  ];

  if (report.faissExposures.length > 0) {
    lines.push(`🔴 FAISS Exposures: ${report.faissExposures.join(", ")}`);
  }
  if (report.langchainEndpoints.length > 0) {
    lines.push(`🔴 LangChain Endpoints: ${report.langchainEndpoints.join(", ")}`);
  }
  if (report.ragEndpoints.length > 0) {
    lines.push(`🟠 RAG Endpoints: ${report.ragEndpoints.join(", ")}`);
  }
  if (report.firebaseExposures.length > 0) {
    lines.push(`🟠 Firebase Exposures: ${report.firebaseExposures.join(", ")}`);
  }
  if (report.jupyterExposures.length > 0) {
    lines.push(`🔴 Jupyter Exposures: ${report.jupyterExposures.join(", ")}`);
  }

  if (report.findings.length === 0) {
    lines.push("No exposed endpoints detected.");
  }

  return lines.join("\n");
}
