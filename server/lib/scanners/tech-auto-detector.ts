/**
 * Technology Auto-Detection Engine
 * =================================
 * Analyzes HTTP responses, headers, passive recon data, and fingerprint
 * results to detect specific technologies (Streamlit, Jupyter, LangChain,
 * FAISS, Firebase, GitHub Actions) and auto-trigger the corresponding
 * scanner modules during the vuln_detection phase.
 *
 * Integration point: Called from the engagement orchestrator after taxonomy
 * enrichment but before nuclei/ZAP scans begin.
 *
 * @author Harrison Cook — AceofCloud
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type DetectableTechnology =
  | "streamlit"
  | "jupyter"
  | "langchain"
  | "faiss"
  | "firebase"
  | "github_actions";

export interface TechDetectionSignal {
  technology: DetectableTechnology;
  confidence: number; // 0-1
  evidence: string[];
  source: "headers" | "html" | "technologies" | "ports" | "dns" | "passive_recon" | "url_pattern" | "github_repo";
}

export interface TechDetectionResult {
  /** All detected technologies with confidence scores */
  detections: TechDetectionSignal[];
  /** Unique technologies detected above threshold */
  confirmedTechnologies: DetectableTechnology[];
  /** Recommended scanner modules to activate */
  recommendedScanners: Array<{
    technology: DetectableTechnology;
    scannerModule: string;
    priority: number; // 1=highest
    rationale: string;
  }>;
  /** Generated test plan items from all detected technologies */
  testPlanItems: string[];
  /** Total detection time in ms */
  detectionTimeMs: number;
}

export interface AssetSignals {
  hostname: string;
  ip?: string;
  headers?: Record<string, string>;
  html?: string;
  technologies?: string[];
  ports?: Array<{ port: number; service: string; version?: string }>;
  passiveRecon?: {
    technologies?: string[];
    cloudProvider?: string;
    riskSignals?: Array<{ severity: string; rationale: string }>;
  };
  /** GitHub repo URL if this is a source code target */
  repoUrl?: string;
  /** Raw HTTP response body snippets */
  responseSnippets?: string[];
}

// ─── Detection Patterns ─────────────────────────────────────────────────────

const STREAMLIT_PATTERNS = {
  headers: [
    { key: "server", pattern: /streamlit/i, confidence: 0.95 },
    { key: "x-streamlit-version", pattern: /.+/, confidence: 0.99 },
  ],
  html: [
    { pattern: /streamlit/i, confidence: 0.85 },
    { pattern: /stApp/i, confidence: 0.9 },
    { pattern: /_stcore/i, confidence: 0.95 },
    { pattern: /st\.set_page_config/i, confidence: 0.95 },
    { pattern: /streamlit\.io/i, confidence: 0.8 },
  ],
  technologies: [
    { pattern: /streamlit/i, confidence: 0.95 },
  ],
  ports: [
    { port: 8501, confidence: 0.6 },
  ],
};

const JUPYTER_PATTERNS = {
  headers: [
    { key: "server", pattern: /jupyter/i, confidence: 0.95 },
    { key: "x-jupyter-token", pattern: /.+/, confidence: 0.99 },
    { key: "set-cookie", pattern: /jupyter/i, confidence: 0.85 },
  ],
  html: [
    { pattern: /jupyter/i, confidence: 0.8 },
    { pattern: /jupyterlab/i, confidence: 0.9 },
    { pattern: /nbconvert/i, confidence: 0.85 },
    { pattern: /notebook\.js/i, confidence: 0.9 },
    { pattern: /jupyterhub/i, confidence: 0.95 },
    { pattern: /kernelgateway/i, confidence: 0.9 },
  ],
  technologies: [
    { pattern: /jupyter/i, confidence: 0.95 },
    { pattern: /ipython/i, confidence: 0.7 },
  ],
  ports: [
    { port: 8888, confidence: 0.5 },
    { port: 8889, confidence: 0.5 },
    { port: 8890, confidence: 0.5 },
  ],
  urlPatterns: [
    { pattern: /\/api\/kernels/i, confidence: 0.95 },
    { pattern: /\/api\/contents/i, confidence: 0.9 },
    { pattern: /\/notebooks\//i, confidence: 0.85 },
    { pattern: /\/lab\//i, confidence: 0.6 },
  ],
};

const LANGCHAIN_PATTERNS = {
  html: [
    { pattern: /langchain/i, confidence: 0.85 },
    { pattern: /langserve/i, confidence: 0.95 },
    { pattern: /\/invoke\b/i, confidence: 0.4 },
    { pattern: /\/stream\b/i, confidence: 0.3 },
  ],
  technologies: [
    { pattern: /langchain/i, confidence: 0.95 },
    { pattern: /langserve/i, confidence: 0.95 },
    { pattern: /langsmith/i, confidence: 0.8 },
  ],
  urlPatterns: [
    { pattern: /\/invoke$/i, confidence: 0.7 },
    { pattern: /\/stream$/i, confidence: 0.6 },
    { pattern: /\/playground/i, confidence: 0.7 },
    { pattern: /langserve/i, confidence: 0.95 },
  ],
  responsePatterns: [
    { pattern: /AgentExecutor/i, confidence: 0.9 },
    { pattern: /langchain_core/i, confidence: 0.95 },
    { pattern: /langchain_community/i, confidence: 0.95 },
    { pattern: /ConversationChain/i, confidence: 0.85 },
    { pattern: /RetrievalQA/i, confidence: 0.85 },
  ],
};

const FAISS_PATTERNS = {
  html: [
    { pattern: /faiss/i, confidence: 0.8 },
    { pattern: /vector.*search/i, confidence: 0.5 },
    { pattern: /embedding/i, confidence: 0.4 },
  ],
  technologies: [
    { pattern: /faiss/i, confidence: 0.95 },
    { pattern: /vector.*db/i, confidence: 0.6 },
    { pattern: /pinecone/i, confidence: 0.3 },
    { pattern: /chroma/i, confidence: 0.3 },
  ],
  urlPatterns: [
    { pattern: /\.faiss$/i, confidence: 0.99 },
    { pattern: /\.pkl$/i, confidence: 0.6 },
    { pattern: /\/embeddings/i, confidence: 0.5 },
    { pattern: /\/vector/i, confidence: 0.4 },
    { pattern: /\/search.*embed/i, confidence: 0.6 },
  ],
  responsePatterns: [
    { pattern: /faiss\.IndexFlat/i, confidence: 0.95 },
    { pattern: /faiss_index/i, confidence: 0.9 },
    { pattern: /vector_store/i, confidence: 0.7 },
    { pattern: /embedding_model/i, confidence: 0.6 },
  ],
};

const FIREBASE_PATTERNS = {
  html: [
    { pattern: /firebase/i, confidence: 0.85 },
    { pattern: /firebaseapp\.com/i, confidence: 0.95 },
    { pattern: /firebaseio\.com/i, confidence: 0.95 },
    { pattern: /firebase\.initializeApp/i, confidence: 0.99 },
    { pattern: /apiKey.*firebase/i, confidence: 0.95 },
    { pattern: /firestore/i, confidence: 0.85 },
  ],
  technologies: [
    { pattern: /firebase/i, confidence: 0.95 },
    { pattern: /firestore/i, confidence: 0.9 },
    { pattern: /google.*cloud.*functions/i, confidence: 0.7 },
  ],
  dns: [
    { pattern: /firebaseapp\.com/i, confidence: 0.95 },
    { pattern: /firebaseio\.com/i, confidence: 0.95 },
    { pattern: /cloudfunctions\.net/i, confidence: 0.8 },
  ],
  headers: [
    { key: "x-powered-by", pattern: /firebase/i, confidence: 0.9 },
    { key: "server", pattern: /google.*frontend/i, confidence: 0.5 },
  ],
};

const GITHUB_ACTIONS_PATTERNS = {
  technologies: [
    { pattern: /github.*action/i, confidence: 0.9 },
    { pattern: /github.*ci/i, confidence: 0.6 },
  ],
  repoPatterns: [
    { pattern: /\.github\/workflows/i, confidence: 0.99 },
    { pattern: /github-actions/i, confidence: 0.9 },
  ],
};

// ─── Detection Engine ───────────────────────────────────────────────────────

/**
 * Detect a single technology from asset signals
 */
function detectTechnology(
  tech: DetectableTechnology,
  patterns: any,
  signals: AssetSignals,
): TechDetectionSignal[] {
  const detections: TechDetectionSignal[] = [];

  // Header-based detection
  if (patterns.headers && signals.headers) {
    for (const hp of patterns.headers) {
      const headerVal = signals.headers[hp.key] || signals.headers[hp.key.toLowerCase()];
      if (headerVal && hp.pattern.test(headerVal)) {
        detections.push({
          technology: tech,
          confidence: hp.confidence,
          evidence: [`Header ${hp.key}: ${headerVal.substring(0, 100)}`],
          source: "headers",
        });
      }
    }
  }

  // HTML-based detection
  if (patterns.html && signals.html) {
    for (const hp of patterns.html) {
      if (hp.pattern.test(signals.html)) {
        const match = signals.html.match(hp.pattern);
        detections.push({
          technology: tech,
          confidence: hp.confidence,
          evidence: [`HTML match: ${match?.[0]?.substring(0, 80) || hp.pattern.source}`],
          source: "html",
        });
      }
    }
  }

  // Technology tag detection
  if (patterns.technologies && signals.technologies) {
    const allTechs = [
      ...signals.technologies,
      ...(signals.passiveRecon?.technologies || []),
    ];
    for (const tp of patterns.technologies) {
      const matched = allTechs.find(t => tp.pattern.test(t));
      if (matched) {
        detections.push({
          technology: tech,
          confidence: tp.confidence,
          evidence: [`Technology tag: ${matched}`],
          source: "technologies",
        });
      }
    }
  }

  // Port-based detection
  if (patterns.ports && signals.ports) {
    for (const pp of patterns.ports) {
      if (signals.ports.some(p => p.port === pp.port)) {
        detections.push({
          technology: tech,
          confidence: pp.confidence,
          evidence: [`Port ${pp.port} open`],
          source: "ports",
        });
      }
    }
  }

  // DNS-based detection
  if (patterns.dns && signals.hostname) {
    for (const dp of patterns.dns) {
      if (dp.pattern.test(signals.hostname)) {
        detections.push({
          technology: tech,
          confidence: dp.confidence,
          evidence: [`DNS match: ${signals.hostname}`],
          source: "dns",
        });
      }
    }
  }

  // URL pattern detection
  if (patterns.urlPatterns && signals.responseSnippets) {
    for (const up of patterns.urlPatterns) {
      for (const snippet of signals.responseSnippets) {
        if (up.pattern.test(snippet)) {
          detections.push({
            technology: tech,
            confidence: up.confidence,
            evidence: [`URL/response pattern: ${up.pattern.source}`],
            source: "url_pattern",
          });
          break;
        }
      }
    }
  }

  // Response body pattern detection
  if (patterns.responsePatterns && signals.responseSnippets) {
    for (const rp of patterns.responsePatterns) {
      for (const snippet of signals.responseSnippets) {
        if (rp.pattern.test(snippet)) {
          detections.push({
            technology: tech,
            confidence: rp.confidence,
            evidence: [`Response body match: ${rp.pattern.source}`],
            source: "url_pattern",
          });
          break;
        }
      }
    }
  }

  // GitHub repo pattern detection
  if (patterns.repoPatterns && signals.repoUrl) {
    for (const rp of patterns.repoPatterns) {
      if (rp.pattern.test(signals.repoUrl)) {
        detections.push({
          technology: tech,
          confidence: rp.confidence,
          evidence: [`Repo pattern: ${signals.repoUrl}`],
          source: "github_repo",
        });
      }
    }
  }

  return detections;
}

/**
 * Aggregate confidence for a technology from multiple signals.
 * Uses 1 - product(1 - ci) formula for independent evidence.
 */
function aggregateConfidence(signals: TechDetectionSignal[]): number {
  if (signals.length === 0) return 0;
  if (signals.length === 1) return signals[0].confidence;
  // P(at least one correct) = 1 - product(1 - ci)
  const product = signals.reduce((acc, s) => acc * (1 - s.confidence), 1);
  return Math.min(1 - product, 0.99);
}

// ─── Scanner Module Mapping ─────────────────────────────────────────────────

const SCANNER_MODULE_MAP: Record<DetectableTechnology, {
  module: string;
  priority: number;
  rationale: string;
}> = {
  streamlit: {
    module: "scanners/streamlit-scanner",
    priority: 1,
    rationale: "Streamlit detected — test for unauthenticated access, widget manipulation, HTML injection, session poisoning, and known CVEs",
  },
  jupyter: {
    module: "scanners/jupyter-scanner",
    priority: 1,
    rationale: "Jupyter detected — test for unauthenticated kernel access, token brute-force, notebook file exposure, path traversal, and RCE via kernel",
  },
  langchain: {
    module: "scanners/langchain-agent-scanner",
    priority: 1,
    rationale: "LangChain detected — test for tool injection, agent memory poisoning, guardrail bypass, RAG manipulation, and dangerous tool exposure",
  },
  faiss: {
    module: "scanners/faiss-vector-scanner",
    priority: 2,
    rationale: "FAISS detected — test for exposed index files (.faiss/.pkl), pickle deserialization RCE, embedding extraction, and vector poisoning",
  },
  firebase: {
    module: "scanners/firebase-scanner",
    priority: 1,
    rationale: "Firebase detected — test for Firestore rules misconfiguration, auth bypass, exposed config keys, and Cloud Functions unauthenticated invocation",
  },
  github_actions: {
    module: "scanners/github-actions-scanner",
    priority: 2,
    rationale: "GitHub Actions detected — test for expression injection, pull_request_target abuse, unpinned actions, self-hosted runner abuse, and secret exposure",
  },
};

// ─── Main Detection Function ────────────────────────────────────────────────

/** Confidence threshold for considering a technology "confirmed" */
const CONFIRMATION_THRESHOLD = 0.6;

/**
 * Run technology auto-detection across all asset signals.
 * Returns confirmed technologies and recommended scanner modules.
 */
export function detectTechnologies(assets: AssetSignals[]): TechDetectionResult {
  const startTime = Date.now();
  const allDetections: TechDetectionSignal[] = [];

  const techPatternMap: Record<DetectableTechnology, any> = {
    streamlit: STREAMLIT_PATTERNS,
    jupyter: JUPYTER_PATTERNS,
    langchain: LANGCHAIN_PATTERNS,
    faiss: FAISS_PATTERNS,
    firebase: FIREBASE_PATTERNS,
    github_actions: GITHUB_ACTIONS_PATTERNS,
  };

  // Run detection for each asset against each technology
  for (const asset of assets) {
    for (const [tech, patterns] of Object.entries(techPatternMap)) {
      const signals = detectTechnology(tech as DetectableTechnology, patterns, asset);
      allDetections.push(...signals);
    }
  }

  // Group by technology and aggregate confidence
  const techGroups = new Map<DetectableTechnology, TechDetectionSignal[]>();
  for (const d of allDetections) {
    const existing = techGroups.get(d.technology) || [];
    existing.push(d);
    techGroups.set(d.technology, existing);
  }

  // Determine confirmed technologies
  const confirmedTechnologies: DetectableTechnology[] = [];
  for (const [tech, signals] of techGroups) {
    const aggregated = aggregateConfidence(signals);
    if (aggregated >= CONFIRMATION_THRESHOLD) {
      confirmedTechnologies.push(tech);
    }
  }

  // Build recommended scanners
  const recommendedScanners = confirmedTechnologies.map(tech => ({
    technology: tech,
    scannerModule: SCANNER_MODULE_MAP[tech].module,
    priority: SCANNER_MODULE_MAP[tech].priority,
    rationale: SCANNER_MODULE_MAP[tech].rationale,
  })).sort((a, b) => a.priority - b.priority);

  // Generate test plan items from confirmed technologies
  const testPlanItems: string[] = [];
  for (const tech of confirmedTechnologies) {
    try {
      switch (tech) {
        case "streamlit": {
          const { generateStreamlitTestPlan } = require("./streamlit-scanner");
          testPlanItems.push(...generateStreamlitTestPlan({
            version: "unknown", port: 8501, hasAuth: false,
            customComponents: [], exposedWidgets: [],
          }));
          break;
        }
        case "jupyter": {
          const { generateJupyterTestPlan } = require("./jupyter-scanner");
          testPlanItems.push(...generateJupyterTestPlan({
            type: "notebook", version: "unknown", port: 8888,
            hasToken: false, hasPassword: false, kernels: [],
            exposedEndpoints: [],
          }));
          break;
        }
        case "langchain": {
          const { generateLangChainTestPlan } = require("./langchain-agent-scanner");
          testPlanItems.push(...generateLangChainTestPlan({
            agentType: "unknown", tools: [], memoryType: "unknown",
            hasGuardrails: false, hasRAG: false, exposedEndpoints: [],
          }));
          break;
        }
        case "faiss": {
          const { generateFAISSTestPlan } = require("./faiss-vector-scanner");
          testPlanItems.push(...generateFAISSTestPlan({
            indexType: "unknown", dimensions: 0, hasPickle: false,
            exposedPaths: [], hasAPI: false,
          }));
          break;
        }
        case "firebase": {
          const { generateFirebaseTestPlan } = require("./firebase-scanner");
          testPlanItems.push(...generateFirebaseTestPlan({
            projectId: "unknown", hasFirestore: false, hasAuth: false,
            hasCloudFunctions: false, hasStorage: false,
            exposedConfig: false,
          }));
          break;
        }
        case "github_actions": {
          const { generateGHActionsTestPlan } = require("./github-actions-scanner");
          testPlanItems.push(...generateGHActionsTestPlan({
            repoUrl: "unknown", workflowCount: 0,
            hasExpressionInjection: false, hasPRTargetTrigger: false,
            unpinnedActions: [], selfHostedRunners: false,
          }));
          break;
        }
      }
    } catch (e: any) {
      testPlanItems.push(`[${tech}] Test plan generation failed: ${e.message}`);
    }
  }

  return {
    detections: allDetections,
    confirmedTechnologies,
    recommendedScanners,
    testPlanItems,
    detectionTimeMs: Date.now() - startTime,
  };
}

/**
 * Build a human-readable summary of detected technologies for the ops log.
 */
export function formatDetectionSummary(result: TechDetectionResult): string {
  if (result.confirmedTechnologies.length === 0) {
    return "No specialized technologies detected (Streamlit, Jupyter, LangChain, FAISS, Firebase, GitHub Actions).";
  }
  const lines = result.confirmedTechnologies.map(tech => {
    const signals = result.detections.filter(d => d.technology === tech);
    const confidence = aggregateConfidence(signals);
    const evidence = signals.map(s => s.evidence[0]).slice(0, 3).join("; ");
    return `• ${tech.toUpperCase()} (${Math.round(confidence * 100)}% confidence) — ${evidence}`;
  });
  return `Detected ${result.confirmedTechnologies.length} specialized technologies:\n${lines.join("\n")}`;
}

/**
 * Build orchestrator-compatible scanner activation commands.
 * Returns an array of scanner activation objects that the orchestrator
 * can use to trigger technology-specific scans.
 */
export function buildScannerActivations(result: TechDetectionResult): Array<{
  technology: DetectableTechnology;
  module: string;
  priority: number;
  testPlanItems: string[];
}> {
  return result.recommendedScanners.map(scanner => ({
    technology: scanner.technology,
    module: scanner.scannerModule,
    priority: scanner.priority,
    testPlanItems: result.testPlanItems.filter(item =>
      item.toLowerCase().includes(scanner.technology.replace("_", " "))
      || item.toLowerCase().includes(scanner.technology.replace("_actions", ""))
    ),
  }));
}
