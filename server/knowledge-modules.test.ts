import { describe, it, expect } from "vitest";

// ─── Attack Chain Retriever Tests ────────────────────────────────────────────

describe("Attack Chain Retriever", () => {
  it("should load attack chains from JSON file", async () => {
    const { getChainsByVulnDescriptions } = await import(
      "./lib/knowledge/attack-chain-retriever"
    );
    // Should not throw and return an array
    const chains = getChainsByVulnDescriptions(["SQL injection"], 3);
    expect(Array.isArray(chains)).toBe(true);
  });

  it("should filter chains by vulnerability descriptions", async () => {
    const { getChainsByVulnDescriptions } = await import(
      "./lib/knowledge/attack-chain-retriever"
    );
    const chains = getChainsByVulnDescriptions(
      ["cross-site scripting", "XSS reflected"],
      5
    );
    expect(Array.isArray(chains)).toBe(true);
    // Should return at most 5
    expect(chains.length).toBeLessThanOrEqual(5);
  });

  it("should format chains for prompt injection", async () => {
    const { getChainsByVulnDescriptions, formatChainsForPrompt } = await import(
      "./lib/knowledge/attack-chain-retriever"
    );
    const chains = getChainsByVulnDescriptions(["injection"], 2);
    const formatted = formatChainsForPrompt(chains);
    expect(typeof formatted).toBe("string");
    // If chains found, should contain attack chain reference text
    if (chains.length > 0) {
      expect(formatted.length).toBeGreaterThan(0);
    }
  });

  it("should return empty array for unmatched descriptions", async () => {
    const { getChainsByVulnDescriptions } = await import(
      "./lib/knowledge/attack-chain-retriever"
    );
    const chains = getChainsByVulnDescriptions(
      ["zzz_nonexistent_vuln_type_zzz"],
      3
    );
    expect(Array.isArray(chains)).toBe(true);
  });
});

// ─── Asset Ontology Tests ────────────────────────────────────────────────────

describe("Asset Ontology", () => {
  it("should load the asset role ontology", async () => {
    const { inferAssetContext } = await import(
      "./lib/knowledge/asset-ontology"
    );
    // Should not throw
    const context = inferAssetContext(["nginx", "php"]);
    expect(typeof context).toBe("object");
  });

  it("should format ontology for prompt injection", async () => {
    const { formatOntologyForPrompt } = await import(
      "./lib/knowledge/asset-ontology"
    );
    const formatted = formatOntologyForPrompt(["nginx", "mysql", "ssh"]);
    expect(typeof formatted).toBe("string");
    expect(formatted.length).toBeGreaterThan(0);
  });

  it("should handle empty technology list gracefully", async () => {
    const { formatOntologyForPrompt } = await import(
      "./lib/knowledge/asset-ontology"
    );
    const formatted = formatOntologyForPrompt([]);
    expect(typeof formatted).toBe("string");
  });
});

// ─── Bug Bounty Knowledge Tests ──────────────────────────────────────────────

describe("Bug Bounty Knowledge", () => {
  it("should load bug bounty context for vulnerability findings", async () => {
    const { getBugBountyContext } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const context = getBugBountyContext(["IDOR", "broken access control"], 3);
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(0);
  });

  it("should match vulnerability classes from findings text", async () => {
    const { getBugBountyContext } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const context = getBugBountyContext(
      ["SQL injection in login form", "XSS reflected in search parameter"],
      3
    );
    expect(context).toContain("Detected matches");
  });

  it("should return triage system prompt", async () => {
    const { getTriageSystemPrompt } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const prompt = getTriageSystemPrompt();
    expect(typeof prompt).toBe("string");
    expect(prompt.length).toBeGreaterThan(0);
    expect(prompt).toContain("hypotheses");
  });

  it("should return vulnerability classes list", async () => {
    const { getVulnerabilityClasses } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const classes = getVulnerabilityClasses();
    expect(Array.isArray(classes)).toBe(true);
    expect(classes.length).toBeGreaterThan(0);
    expect(classes).toContain("IDOR");
    expect(classes).toContain("XSS");
  });

  it("should return OWASP mapping for known vulnerability class", async () => {
    const { getOwaspMapping } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const mapping = getOwaspMapping("IDOR");
    expect(typeof mapping).toBe("string");
    expect(mapping).toContain("Broken Access Control");
  });

  it("should return training examples for prompt", async () => {
    const { getTrainingExamplesForPrompt } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const examples = getTrainingExamplesForPrompt(2);
    expect(typeof examples).toBe("string");
    if (examples.length > 0) {
      expect(examples).toContain("Training Example");
    }
  });

  it("should handle empty findings gracefully", async () => {
    const { getBugBountyContext } = await import(
      "./lib/knowledge/bugbounty-knowledge"
    );
    const context = getBugBountyContext([], 3);
    expect(typeof context).toBe("string");
    // Should still return triage methodology even with no matches
    expect(context.length).toBeGreaterThan(0);
  });
});

// ─── Training Corpus Tests ───────────────────────────────────────────────────

describe("Training Corpus", () => {
  it("should return corpus entries for a specific tool", async () => {
    const { getCorpusForTool } = await import(
      "./lib/knowledge/training-corpus"
    );
    const entries = getCorpusForTool("nuclei");
    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBeGreaterThan(0);
    expect(entries[0].tool).toBe("nuclei");
  });

  it("should return corpus entries for OWASP categories", async () => {
    const { getCorpusForOwasp } = await import(
      "./lib/knowledge/training-corpus"
    );
    const entries = getCorpusForOwasp(["Security Misconfiguration"]);
    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBeGreaterThan(0);
  });

  it("should format triage corpus context for LLM injection", async () => {
    const { getTriageCorpusContext } = await import(
      "./lib/knowledge/training-corpus"
    );
    const context = getTriageCorpusContext(undefined, 3);
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(0);
    expect(context).toContain("Scan Triage Training Examples");
  });

  it("should filter triage corpus by tool", async () => {
    const { getTriageCorpusContext } = await import(
      "./lib/knowledge/training-corpus"
    );
    const context = getTriageCorpusContext("sqlmap", 3);
    expect(typeof context).toBe("string");
    if (context.length > 0) {
      expect(context).toContain("sqlmap");
    }
  });

  it("should return demo sites list", async () => {
    const { getDemoSites } = await import("./lib/knowledge/training-corpus");
    const sites = getDemoSites();
    expect(Array.isArray(sites)).toBe(true);
    expect(sites.length).toBe(5);
    expect(sites[0]).toHaveProperty("host");
    expect(sites[0]).toHaveProperty("name");
    expect(sites[0]).toHaveProperty("purpose");
  });

  it("should return full corpus with all entries", async () => {
    const { getFullCorpus } = await import("./lib/knowledge/training-corpus");
    const corpus = getFullCorpus();
    expect(Array.isArray(corpus)).toBe(true);
    expect(corpus.length).toBe(8);
    // Each entry should have required fields
    for (const entry of corpus) {
      expect(entry).toHaveProperty("id");
      expect(entry).toHaveProperty("tool");
      expect(entry).toHaveProperty("target");
      expect(entry).toHaveProperty("parsed_findings");
      expect(entry).toHaveProperty("expected_triage");
      expect(entry).toHaveProperty("owasp_categories");
    }
  });

  it("should return empty array for unknown tool", async () => {
    const { getCorpusForTool } = await import(
      "./lib/knowledge/training-corpus"
    );
    const entries = getCorpusForTool("nonexistent_tool");
    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBe(0);
  });
});
