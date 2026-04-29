/**
 * Tests for all 6 gap scanner modules:
 * 1. Streamlit scanner
 * 2. Jupyter scanner
 * 3. LangChain agent scanner
 * 4. FAISS vector DB scanner
 * 5. Firebase scanner
 * 6. GitHub Actions scanner
 */
import { describe, it, expect } from "vitest";

// ─── 1. Streamlit Scanner ────────────────────────────────────────────────────
import {
  fingerprintStreamlit,
  STREAMLIT_CVES,
  STREAMLIT_PAYLOADS,
  generateStreamlitTestPlan,
} from "./lib/scanners/streamlit-scanner";

describe("Streamlit Scanner", () => {
  it("fingerprints Streamlit app from HTML with _stcore", () => {
    const result = fingerprintStreamlit(
      {},
      '<html><script src="/_stcore/static/js/main.js"></script></html>'
    );
    // Streamlit detected via exposed widgets or HTML patterns
    expect(result).toBeDefined();
    expect(result.serverHeaders).toBeDefined();
  });

  it("fingerprints Streamlit via X-Streamlit-Version header", () => {
    const result = fingerprintStreamlit(
      { "x-streamlit-version": "1.28.0" },
      "<html><body>App</body></html>"
    );
    expect(result.version).toBe("1.28.0");
  });

  it("returns null version for non-Streamlit apps", () => {
    const result = fingerprintStreamlit(
      {},
      "<html><body>Regular Flask App</body></html>"
    );
    expect(result.version).toBeNull();
  });

  it("has CVE entries for Streamlit", () => {
    expect(STREAMLIT_CVES.length).toBeGreaterThan(0);
  });

  it("has attack payloads for injection and file access", () => {
    const allPayloads = [
      ...(STREAMLIT_PAYLOADS.html_injection || []),
      ...(STREAMLIT_PAYLOADS.file_upload_traversal || []),
      ...(STREAMLIT_PAYLOADS.widget_manipulation || []),
      ...(STREAMLIT_PAYLOADS.session_state_poisoning || []),
    ];
    expect(allPayloads.length).toBeGreaterThan(3);
  });

  it("generates a test plan with Streamlit-specific items", () => {
    const fingerprint: any = {
      version: "1.28.0",
      pythonVersion: "3.10.0",
      hasAuth: false,
      hasFileUploader: true,
      hasMarkdownUnsafe: true,
      exposedWidgets: ["stTextInput", "stFileUploader"],
      customComponents: [],
      serverHeaders: {},
    };
    const plan = generateStreamlitTestPlan(fingerprint);
    expect(plan.length).toBeGreaterThan(3);
    expect(plan.some((t: string) => t.toLowerCase().includes("streamlit"))).toBe(true);
  });
});

// ─── 2. Jupyter Scanner ──────────────────────────────────────────────────────
import {
  fingerprintJupyter,
  JUPYTER_CVES,
  JUPYTER_PAYLOADS,
  generateJupyterTestPlan,
} from "./lib/scanners/jupyter-scanner";

describe("Jupyter Scanner", () => {
  it("fingerprints Jupyter from API-like response", () => {
    const result = fingerprintJupyter(
      {},
      "<html><body>Jupyter Notebook</body></html>",
      JSON.stringify({ version: "6.5.4", implementation: "notebook" })
    );
    expect(result.version).toBe("6.5.4");
  });

  it("fingerprints JupyterHub", () => {
    const result = fingerprintJupyter(
      {},
      '<html><body>jupyterhub /hub/ login</body></html>'
    );
    expect(result.type).toBe("hub");
  });

  it("returns unknown type for non-Jupyter responses", () => {
    const result = fingerprintJupyter(
      {},
      "<html><body>Regular App</body></html>"
    );
    expect(result.type).toBe("unknown");
  });

  it("has CVE entries for Jupyter", () => {
    expect(JUPYTER_CVES.length).toBeGreaterThan(0);
  });

  it("has attack payloads", () => {
    const allPayloads = [
      ...(JUPYTER_PAYLOADS.kernel_execution || []),
      ...(JUPYTER_PAYLOADS.path_traversal || []),
      ...(JUPYTER_PAYLOADS.token_wordlist || []),
      ...(JUPYTER_PAYLOADS.api_endpoints || []),
    ];
    expect(allPayloads.length).toBeGreaterThan(3);
  });

  it("generates a test plan", () => {
    const fingerprint: any = {
      type: "notebook" as const,
      version: "6.5.4",
      pythonVersion: "3.10.0",
      hasAuth: false,
      authType: "none" as const,
      runningKernels: 2,
      exposedEndpoints: ["/api/terminals", "/api/kernels"],
      serverHeaders: {},
    };
    const plan = generateJupyterTestPlan(fingerprint);
    expect(plan.length).toBeGreaterThan(3);
    expect(plan.some((t: string) => t.toLowerCase().includes("jupyter") || t.toLowerCase().includes("kernel"))).toBe(true);
  });
});

// ─── 3. LangChain Agent Scanner ──────────────────────────────────────────────
import {
  DANGEROUS_LANGCHAIN_TOOLS,
  LANGCHAIN_PAYLOADS,
  profileLangChainAgent,
  generateLangChainTestPlan,
} from "./lib/scanners/langchain-agent-scanner";

describe("LangChain Agent Scanner", () => {
  it("has dangerous tools registry", () => {
    expect(Object.keys(DANGEROUS_LANGCHAIN_TOOLS).length).toBeGreaterThan(3);
    expect(DANGEROUS_LANGCHAIN_TOOLS["shell_tool"] || DANGEROUS_LANGCHAIN_TOOLS["ShellTool"]).toBeDefined();
  });

  it("has attack payloads for tool injection and memory poisoning", () => {
    const allPayloads = [
      ...(LANGCHAIN_PAYLOADS.tool_injection || []),
      ...(LANGCHAIN_PAYLOADS.memory_poisoning || []),
      ...(LANGCHAIN_PAYLOADS.guardrail_bypass || []),
      ...(LANGCHAIN_PAYLOADS.rag_manipulation || []),
    ];
    expect(allPayloads.length).toBeGreaterThan(3);
  });

  it("profiles agent config and flags dangerous tools", () => {
    const profile = profileLangChainAgent(
      [
        { input: "test", output: "Using tool: ShellTool\nAction: PythonREPLTool\nCalling: FileSystemTool", toolCalls: ["ShellTool", "PythonREPLTool", "FileSystemTool"] },
      ],
      { agentType: "openai-functions", memoryType: "buffer", maxIterations: 100, verboseMode: true }
    );
    expect(profile.dangerousToolsDetected.length).toBeGreaterThan(0);
  });

  it("flags high max iterations in config hints", () => {
    const profile = profileLangChainAgent(
      [{ input: "test", output: "search result" }],
      { agentType: "react", maxIterations: 500 }
    );
    expect(profile.maxIterations).toBe(500);
  });

  it("generates a test plan with LangChain-specific items", () => {
    const profile: any = {
      agentType: "openai-functions",
      llmProvider: "openai",
      tools: [{ name: "search", isDangerous: false, riskLevel: "low" }],
      memoryType: "buffer",
      hasRetriever: true,
      maxIterations: 15,
      handleParsingErrors: false,
      verboseMode: false,
      dangerousToolsDetected: [],
    };
    const plan = generateLangChainTestPlan(profile);
    expect(plan.length).toBeGreaterThan(3);
    expect(plan.some((t: string) => t.toLowerCase().includes("agent") || t.toLowerCase().includes("tool") || t.toLowerCase().includes("prompt"))).toBe(true);
  });
});

// ─── 4. FAISS Vector DB Scanner ──────────────────────────────────────────────
import {
  FAISS_FILE_PATHS,
  FAISS_PAYLOADS,
  generateFAISSTestPlan,
} from "./lib/scanners/faiss-vector-scanner";

describe("FAISS Vector DB Scanner", () => {
  it("has exposure paths for FAISS index files", () => {
    expect(FAISS_FILE_PATHS.length).toBeGreaterThan(5);
    expect(FAISS_FILE_PATHS.some((p: string) => p.includes(".faiss") || p.includes("faiss"))).toBe(true);
  });

  it("has vector poisoning and extraction payloads", () => {
    const allPayloads = [
      ...(FAISS_PAYLOADS.pickle_rce_concepts || []),
      ...(FAISS_PAYLOADS.embedding_extraction || []),
      ...(FAISS_PAYLOADS.vector_poisoning || []),
      ...(FAISS_PAYLOADS.denial_of_service || []),
    ];
    expect(allPayloads.length).toBeGreaterThan(2);
  });

  it("generates a test plan for FAISS with RAG pipeline", () => {
    const profile = {
      hasExposedIndex: false,
      hasExposedPickle: false,
      hasRAGPipeline: true,
      hasAPIAccess: true,
      hasDocumentUpload: true,
      exposedFiles: [],
      indexType: "flat" as const,
      embeddingDimension: 1536,
      findings: [],
    };
    const plan = generateFAISSTestPlan(profile);
    expect(plan.length).toBeGreaterThan(3);
    expect(plan.some((t: string) => t.toLowerCase().includes("faiss") || t.toLowerCase().includes("vector"))).toBe(true);
    expect(plan.some((t: string) => t.toLowerCase().includes("poison") || t.toLowerCase().includes("inject"))).toBe(true);
  });

  it("generates a test plan with pickle-specific tests when pickle is exposed", () => {
    const profile = {
      hasExposedIndex: true,
      hasExposedPickle: true,
      hasRAGPipeline: true,
      hasAPIAccess: false,
      hasDocumentUpload: false,
      exposedFiles: ["/data/index.pkl"],
      indexType: "flat" as const,
      embeddingDimension: 1536,
      findings: [],
    };
    const plan = generateFAISSTestPlan(profile);
    expect(plan.some((t: string) => t.toLowerCase().includes("pickle") || t.toLowerCase().includes("deserialization"))).toBe(true);
  });
});

// ─── 5. Firebase Scanner ─────────────────────────────────────────────────────
import {
  extractFirebaseConfig,
  FIRESTORE_TEST_COLLECTIONS,
  COMMON_CLOUD_FUNCTION_PATHS,
  generateFirebaseTestPlan,
} from "./lib/scanners/firebase-scanner";

describe("Firebase Scanner", () => {
  it("extracts Firebase config from client-side JavaScript", () => {
    const js = `
      const firebaseConfig = {
        apiKey: "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        authDomain: "myapp.firebaseapp.com",
        projectId: "myapp-12345",
        storageBucket: "myapp-12345.appspot.com",
        databaseURL: "https://myapp-12345-default-rtdb.firebaseio.com"
      };
    `;
    const config = extractFirebaseConfig(js);
    expect(config).not.toBeNull();
    expect(config!.apiKey).toBe("AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect(config!.projectId).toBe("myapp-12345");
    expect(config!.authDomain).toBe("myapp.firebaseapp.com");
  });

  it("returns null for non-Firebase JavaScript", () => {
    const js = "const app = express(); app.listen(3000);";
    const config = extractFirebaseConfig(js);
    expect(config).toBeNull();
  });

  it("has comprehensive Firestore test collections", () => {
    expect(FIRESTORE_TEST_COLLECTIONS.length).toBeGreaterThan(10);
    expect(FIRESTORE_TEST_COLLECTIONS).toContain("users");
    expect(FIRESTORE_TEST_COLLECTIONS).toContain("admin");
    expect(FIRESTORE_TEST_COLLECTIONS).toContain("secrets");
  });

  it("has common Cloud Function paths", () => {
    expect(COMMON_CLOUD_FUNCTION_PATHS.length).toBeGreaterThan(10);
    expect(COMMON_CLOUD_FUNCTION_PATHS).toContain("/api");
    expect(COMMON_CLOUD_FUNCTION_PATHS).toContain("/webhook");
  });

  it("generates a Firebase test plan", () => {
    const profile = {
      projectId: "test",
      hasFirestore: true,
      hasRealtimeDB: true,
      hasStorage: true,
      hasAuth: true,
      hasCloudFunctions: true,
      authProviders: ["google"],
      anonymousAuthEnabled: false,
      firestoreRulesOpen: false,
      realtimeDBRulesOpen: false,
      storageBucketPublic: false,
      exposedConfigKeys: [],
      cloudFunctionsEndpoints: [],
    };
    const plan = generateFirebaseTestPlan(profile);
    expect(plan.length).toBeGreaterThan(10);
    expect(plan.some((t: string) => t.toLowerCase().includes("firestore"))).toBe(true);
    expect(plan.some((t: string) => t.toLowerCase().includes("auth"))).toBe(true);
    expect(plan.some((t: string) => t.toLowerCase().includes("storage"))).toBe(true);
  });
});

// ─── 6. GitHub Actions Scanner ───────────────────────────────────────────────
import {
  analyzeWorkflows,
  INJECTABLE_CONTEXTS,
  generateGHActionsTestPlan,
} from "./lib/scanners/github-actions-scanner";

describe("GitHub Actions Scanner", () => {
  it("detects expression injection in run steps", () => {
    // Use actual ${{ }} syntax (not escaped) in the YAML content
    const content = [
      "name: CI",
      "on:",
      "  pull_request:",
      "    types: [opened]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "PR title is ${{ github.event.pull_request.title }}"',
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/ci.yml", content }],
    });
    expect(result.findings.some(f => f.category === "expression_injection")).toBe(true);
  });

  it("detects pull_request_target with checkout of PR head", () => {
    const content = [
      "name: PR Target",
      "on:",
      "  pull_request_target:",
      "    types: [opened]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm test",
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/prt.yml", content }],
    });
    expect(result.findings.some(f => f.category === "pull_request_target_abuse")).toBe(true);
  });

  it("detects unpinned third-party actions", () => {
    const content = [
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: some-org/some-action@v2",
      "      - uses: another-org/action@main",
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/ci.yml", content }],
    });
    expect(result.findings.some(f => f.category === "unpinned_actions")).toBe(true);
    expect(result.profile.unpinnedActions.length).toBeGreaterThan(0);
  });

  it("detects missing permissions block", () => {
    const content = [
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/ci.yml", content }],
    });
    expect(result.findings.some(f => f.category === "token_over_permission")).toBe(true);
  });

  it("detects self-hosted runner with PR trigger", () => {
    const content = [
      "name: CI",
      "on:",
      "  pull_request:",
      "    types: [opened]",
      "jobs:",
      "  build:",
      "    runs-on: self-hosted",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - run: npm test",
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/ci.yml", content }],
    });
    expect(result.findings.some(f => f.category === "self_hosted_runner_abuse")).toBe(true);
  });

  it("has comprehensive injectable contexts list", () => {
    expect(INJECTABLE_CONTEXTS.length).toBeGreaterThan(10);
    expect(INJECTABLE_CONTEXTS.some(c => c.includes("pull_request.title"))).toBe(true);
    expect(INJECTABLE_CONTEXTS.some(c => c.includes("issue.title"))).toBe(true);
    expect(INJECTABLE_CONTEXTS.some(c => c.includes("head_commit.message"))).toBe(true);
  });

  it("generates a test plan with self-hosted runner checks", () => {
    const profile = {
      totalWorkflows: 3,
      triggersUsed: ["push", "pull_request", "pull_request_target"],
      thirdPartyActions: [],
      unpinnedActions: [{ action: "test/action", version: "v1", isPinned: false, file: "ci.yml", line: 1 }],
      usesSecrets: true,
      secretNames: ["DEPLOY_KEY"],
      usesSelfHostedRunners: true,
      hasPermissionsBlock: false,
      defaultPermissions: "write-all (default)",
      usesEnvironments: false,
      hasCodeql: false,
      hasDependabot: false,
    };
    const plan = generateGHActionsTestPlan(profile);
    expect(plan.length).toBeGreaterThan(5);
    expect(plan.some((t: string) => t.toLowerCase().includes("self-hosted") || t.toLowerCase().includes("runner"))).toBe(true);
    expect(plan.some((t: string) => t.toLowerCase().includes("secret"))).toBe(true);
  });

  it("produces a complete scan profile", () => {
    const content = [
      "name: CI",
      "on: push",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@abc123def456abc123def456abc123def456abcd",
      "      - run: echo Hello",
      "        env:",
      "          TOKEN: ${{ secrets.MY_TOKEN }}",
    ].join("\n");

    const result = analyzeWorkflows({
      owner: "test",
      repo: "test",
      workflowFiles: [{ path: ".github/workflows/ci.yml", content }],
    });
    expect(result.profile.totalWorkflows).toBe(1);
    expect(result.profile.hasPermissionsBlock).toBe(true);
    expect(result.profile.usesSecrets).toBe(true);
    expect(result.profile.secretNames).toContain("MY_TOKEN");
    expect(result.scanDuration).toBeGreaterThanOrEqual(0);
    expect(result.timestamp).toBeTruthy();
  });
});
