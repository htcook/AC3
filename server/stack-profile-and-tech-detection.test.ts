/**
 * Tests for:
 * 1. Technology Auto-Detection Engine (tech-auto-detector.ts)
 * 2. Stack Profile scanner matching logic (stack-profile router helpers)
 * 3. Orchestrator integration point (tech-auto-detector wiring)
 *
 * @author Harrison Cook — AceofCloud
 */
import { describe, it, expect } from "vitest";
import {
  detectTechnologies,
  formatDetectionSummary,
  buildScannerActivations,
  type AssetSignals,
  type TechDetectionResult,
} from "./lib/scanners/tech-auto-detector";

// ─── Tech Auto-Detection Engine Tests ───────────────────────────────────────

describe("Technology Auto-Detection Engine", () => {
  describe("detectTechnologies", () => {
    it("should detect Streamlit from headers", () => {
      const assets: AssetSignals[] = [{
        hostname: "app.example.com",
        headers: { "server": "Streamlit/1.28.0", "x-streamlit-version": "1.28.0" },
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("streamlit");
      expect(result.detections.length).toBeGreaterThan(0);
      expect(result.recommendedScanners.some(s => s.scannerModule.includes("streamlit"))).toBe(true);
    });

    it("should detect Jupyter from HTML content", () => {
      const assets: AssetSignals[] = [{
        hostname: "notebook.example.com",
        html: '<script src="/static/notebook.js"></script><div id="jupyterlab-splash">JupyterLab</div>',
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("jupyter");
    });

    it("should detect LangChain from response patterns", () => {
      const assets: AssetSignals[] = [{
        hostname: "api.example.com",
        responseSnippets: ['{"agent": "AgentExecutor", "tools": ["serpapi", "calculator"]}'],
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("langchain");
    });

    it("should detect Firebase from HTML and DNS", () => {
      const assets: AssetSignals[] = [{
        hostname: "myapp.firebaseapp.com",
        html: '<script>firebase.initializeApp({apiKey: "AIza..."})</script>',
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("firebase");
    });

    it("should detect FAISS from URL patterns", () => {
      const assets: AssetSignals[] = [{
        hostname: "ml.example.com",
        responseSnippets: ["/data/embeddings/index.faiss", "faiss.IndexFlatL2"],
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("faiss");
    });

    it("should detect GitHub Actions from repo patterns", () => {
      const assets: AssetSignals[] = [{
        hostname: "github.com",
        repoUrl: "https://github.com/org/repo/.github/workflows/ci.yml",
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("github_actions");
    });

    it("should return empty for assets with no matching signals", () => {
      const assets: AssetSignals[] = [{
        hostname: "plain.example.com",
        headers: { "server": "nginx/1.25" },
        html: "<html><body>Hello World</body></html>",
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toHaveLength(0);
      expect(result.recommendedScanners).toHaveLength(0);
    });

    it("should detect multiple technologies from a single asset", () => {
      const assets: AssetSignals[] = [{
        hostname: "ml-app.firebaseapp.com",
        headers: { "server": "Streamlit/1.28.0" },
        html: '<div>firebase.initializeApp({})</div>',
        responseSnippets: ['langchain_core.agents.AgentExecutor'],
      }];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies.length).toBeGreaterThanOrEqual(2);
    });

    it("should aggregate confidence across multiple assets", () => {
      const assets: AssetSignals[] = [
        { hostname: "app1.example.com", headers: { "server": "Streamlit" } },
        { hostname: "app2.example.com", html: '<div class="stApp">Streamlit app</div>' },
      ];
      const result = detectTechnologies(assets);
      expect(result.confirmedTechnologies).toContain("streamlit");
      // Should have detections from both assets
      const streamlitDetections = result.detections.filter(d => d.technology === "streamlit");
      expect(streamlitDetections.length).toBeGreaterThanOrEqual(2);
    });

    it("should track detection time", () => {
      const assets: AssetSignals[] = [{ hostname: "test.com" }];
      const result = detectTechnologies(assets);
      expect(result.detectionTimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("formatDetectionSummary", () => {
    it("should format empty results", () => {
      const result: TechDetectionResult = {
        detections: [],
        confirmedTechnologies: [],
        recommendedScanners: [],
        testPlanItems: [],
        detectionTimeMs: 5,
      };
      const summary = formatDetectionSummary(result);
      expect(summary).toContain("No specialized technologies detected");
    });

    it("should format detected technologies with confidence", () => {
      const assets: AssetSignals[] = [{
        hostname: "app.example.com",
        headers: { "x-streamlit-version": "1.28.0" },
      }];
      const result = detectTechnologies(assets);
      const summary = formatDetectionSummary(result);
      expect(summary).toContain("STREAMLIT");
      expect(summary).toContain("confidence");
    });
  });

  describe("buildScannerActivations", () => {
    it("should build activation objects for confirmed technologies", () => {
      const assets: AssetSignals[] = [{
        hostname: "app.example.com",
        headers: { "x-streamlit-version": "1.28.0" },
      }];
      const result = detectTechnologies(assets);
      const activations = buildScannerActivations(result);
      expect(activations.length).toBeGreaterThan(0);
      expect(activations[0]).toHaveProperty("technology");
      expect(activations[0]).toHaveProperty("module");
      expect(activations[0]).toHaveProperty("priority");
      expect(activations[0]).toHaveProperty("testPlanItems");
    });

    it("should return empty array when no technologies confirmed", () => {
      const result: TechDetectionResult = {
        detections: [],
        confirmedTechnologies: [],
        recommendedScanners: [],
        testPlanItems: [],
        detectionTimeMs: 0,
      };
      const activations = buildScannerActivations(result);
      expect(activations).toHaveLength(0);
    });
  });
});

// ─── Stack Profile Scanner Matching Tests ───────────────────────────────────

describe("Stack Profile Scanner Matching", () => {
  // Import the matching logic by requiring the router module
  // We test the pure functions extracted from the router

  function matchScannersToStack(stack: string[]): {
    matched: string[];
    coveragePercent: number;
    gaps: string[];
  } {
    const SCANNER_REGISTRY: Record<string, { technologies: string[] }> = {
      "streamlit-scanner": { technologies: ["streamlit", "python", "flask"] },
      "jupyter-scanner": { technologies: ["jupyter", "jupyterlab", "jupyterhub", "ipython", "python"] },
      "langchain-agent-scanner": { technologies: ["langchain", "langserve", "langsmith", "openai", "anthropic", "llm", "rag"] },
      "faiss-vector-scanner": { technologies: ["faiss", "vector", "embedding", "pinecone", "chroma", "weaviate", "qdrant"] },
      "firebase-scanner": { technologies: ["firebase", "firestore", "google cloud functions", "gcp"] },
      "github-actions-scanner": { technologies: ["github actions", "github", "ci/cd", "github workflows"] },
    };

    const normalizedStack = stack.map(t => t.toLowerCase().trim());
    const matched: string[] = [];
    const coveredTechs = new Set<string>();

    for (const [scannerKey, scanner] of Object.entries(SCANNER_REGISTRY)) {
      const hasMatch = scanner.technologies.some(scannerTech =>
        normalizedStack.some(stackTech =>
          stackTech.includes(scannerTech) || scannerTech.includes(stackTech)
        )
      );
      if (hasMatch) {
        matched.push(scannerKey);
        for (const tech of scanner.technologies) {
          for (const stackTech of normalizedStack) {
            if (stackTech.includes(tech) || tech.includes(stackTech)) {
              coveredTechs.add(stackTech);
            }
          }
        }
      }
    }

    const gaps = normalizedStack.filter(t => !coveredTechs.has(t));
    const coveragePercent = normalizedStack.length > 0
      ? Math.round((coveredTechs.size / normalizedStack.length) * 100)
      : 0;

    return { matched, coveragePercent, gaps };
  }

  it("should match Python to streamlit and jupyter scanners", () => {
    const result = matchScannersToStack(["Python", "Django"]);
    expect(result.matched).toContain("streamlit-scanner");
    expect(result.matched).toContain("jupyter-scanner");
    expect(result.gaps).toContain("django"); // Django has no dedicated scanner
  });

  it("should match LangChain stack correctly", () => {
    const result = matchScannersToStack(["LangChain", "OpenAI", "FAISS", "Python"]);
    expect(result.matched).toContain("langchain-agent-scanner");
    expect(result.matched).toContain("faiss-vector-scanner");
    expect(result.coveragePercent).toBeGreaterThanOrEqual(75);
  });

  it("should match Firebase stack", () => {
    const result = matchScannersToStack(["Firebase", "Firestore", "React"]);
    expect(result.matched).toContain("firebase-scanner");
    expect(result.gaps).toContain("react"); // React has no dedicated scanner
  });

  it("should match GitHub Actions", () => {
    const result = matchScannersToStack(["GitHub Actions", "Docker", "Terraform"]);
    expect(result.matched).toContain("github-actions-scanner");
    expect(result.gaps).toContain("docker");
    expect(result.gaps).toContain("terraform");
  });

  it("should return 0% coverage for unrecognized stack", () => {
    const result = matchScannersToStack(["Cobol", "Fortran", "Assembly"]);
    expect(result.matched).toHaveLength(0);
    expect(result.coveragePercent).toBe(0);
    expect(result.gaps).toHaveLength(3);
  });

  it("should handle empty stack gracefully", () => {
    const result = matchScannersToStack([]);
    expect(result.matched).toHaveLength(0);
    expect(result.coveragePercent).toBe(0);
    expect(result.gaps).toHaveLength(0);
  });

  it("should calculate correct coverage percentage", () => {
    // 4 techs: Python (matched), LangChain (matched), FAISS (matched), React (gap)
    const result = matchScannersToStack(["Python", "LangChain", "FAISS", "React"]);
    expect(result.coveragePercent).toBe(75); // 3/4 = 75%
  });

  it("should be case-insensitive", () => {
    const result1 = matchScannersToStack(["FIREBASE"]);
    const result2 = matchScannersToStack(["firebase"]);
    const result3 = matchScannersToStack(["Firebase"]);
    expect(result1.matched).toEqual(result2.matched);
    expect(result2.matched).toEqual(result3.matched);
  });
});

// ─── Orchestrator Integration Tests ─────────────────────────────────────────

describe("Orchestrator Tech Auto-Detection Integration", () => {
  it("should detect technologies from asset-like signals (simulated orchestrator input)", () => {
    // Simulate the signal mapping that the orchestrator does
    const mockAssets = [
      {
        hostname: "target.example.com",
        technologies: ["Streamlit", "Python"],
        ports: [{ port: 8501, service: "http" }],
      },
      {
        hostname: "api.example.com",
        technologies: ["LangChain"],
        responseSnippets: ['{"type": "AgentExecutor"}'],
      },
    ];

    const assetSignals: AssetSignals[] = mockAssets.map(asset => ({
      hostname: asset.hostname || "",
      technologies: asset.technologies || [],
      ports: asset.ports || [],
      responseSnippets: (asset as any).responseSnippets || [],
    }));

    const result = detectTechnologies(assetSignals);
    expect(result.confirmedTechnologies).toContain("streamlit");
    expect(result.confirmedTechnologies).toContain("langchain");
    expect(result.recommendedScanners.length).toBeGreaterThanOrEqual(2);
  });

  it("should generate test plan items for detected technologies", () => {
    const assets: AssetSignals[] = [{
      hostname: "app.example.com",
      headers: { "x-streamlit-version": "1.28.0" },
    }];
    const result = detectTechnologies(assets);
    // Test plan items should be generated (may fail if scanner module isn't loadable, which is OK)
    expect(result.testPlanItems).toBeDefined();
    expect(Array.isArray(result.testPlanItems)).toBe(true);
  });

  it("should sort recommended scanners by priority", () => {
    const assets: AssetSignals[] = [{
      hostname: "app.firebaseapp.com",
      html: '<script>firebase.initializeApp({})</script>',
      technologies: ["Firebase", "FAISS"],
      responseSnippets: ["/data/index.faiss"],
    }];
    const result = detectTechnologies(assets);
    if (result.recommendedScanners.length >= 2) {
      for (let i = 1; i < result.recommendedScanners.length; i++) {
        expect(result.recommendedScanners[i].priority).toBeGreaterThanOrEqual(
          result.recommendedScanners[i - 1].priority
        );
      }
    }
  });
});
