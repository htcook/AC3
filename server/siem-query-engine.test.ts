import { describe, it, expect } from "vitest";
import {
  getDefaultTemplates,
  getQueryLanguage,
  getQuerySyntaxHint,
  substituteQueryVariables,
  extractQueryVariables,
  DEFAULT_QUERY_TEMPLATES,
  type SiemProvider,
  type QueryTemplate,
} from "./lib/siem-query-engine";

/* ═══════════════════════════════════════════════════════════
 * Query Template Tests
 * ═══════════════════════════════════════════════════════════ */

describe("SIEM Query Templates", () => {
  it("should return all default templates when no provider specified", () => {
    const templates = getDefaultTemplates();
    expect(templates.length).toBeGreaterThanOrEqual(10);
    // Should have templates for all providers
    const providers = new Set(templates.map(t => t.provider));
    expect(providers.has("splunk")).toBe(true);
    expect(providers.has("elastic")).toBe(true);
    expect(providers.has("sentinel")).toBe(true);
    expect(providers.has("qradar")).toBe(true);
    expect(providers.has("custom")).toBe(true);
  });

  it("should filter templates by provider", () => {
    const splunkTemplates = getDefaultTemplates("splunk");
    expect(splunkTemplates.length).toBeGreaterThanOrEqual(2);
    expect(splunkTemplates.every(t => t.provider === "splunk")).toBe(true);

    const elasticTemplates = getDefaultTemplates("elastic");
    expect(elasticTemplates.length).toBeGreaterThanOrEqual(2);
    expect(elasticTemplates.every(t => t.provider === "elastic")).toBe(true);
  });

  it("each template should have required fields", () => {
    for (const t of DEFAULT_QUERY_TEMPLATES) {
      expect(t.id).toBeTruthy();
      expect(t.name).toBeTruthy();
      expect(t.provider).toBeTruthy();
      expect(t.query).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(Array.isArray(t.variables)).toBe(true);
      expect(t.variables.length).toBeGreaterThan(0);
    }
  });

  it("each template should have unique IDs", () => {
    const ids = DEFAULT_QUERY_TEMPLATES.map(t => t.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("template variables should match placeholders in query", () => {
    for (const t of DEFAULT_QUERY_TEMPLATES) {
      const extracted = extractQueryVariables(t.query);
      for (const v of t.variables) {
        expect(extracted).toContain(v);
      }
    }
  });
});

/* ═══════════════════════════════════════════════════════════
 * Query Language Info Tests
 * ═══════════════════════════════════════════════════════════ */

describe("Query Language Info", () => {
  const providers: SiemProvider[] = ["splunk", "elastic", "sentinel", "qradar", "custom"];

  it("should return language name for each provider", () => {
    for (const p of providers) {
      const lang = getQueryLanguage(p);
      expect(lang).toBeTruthy();
      expect(typeof lang).toBe("string");
    }
  });

  it("should return correct language names", () => {
    expect(getQueryLanguage("splunk")).toContain("SPL");
    expect(getQueryLanguage("elastic")).toContain("Elasticsearch");
    expect(getQueryLanguage("sentinel")).toContain("KQL");
    expect(getQueryLanguage("qradar")).toContain("AQL");
  });

  it("should return syntax hint for each provider", () => {
    for (const p of providers) {
      const hint = getQuerySyntaxHint(p);
      expect(hint).toBeTruthy();
      expect(typeof hint).toBe("string");
      expect(hint.length).toBeGreaterThan(20);
    }
  });

  it("syntax hints should contain provider-appropriate content", () => {
    expect(getQuerySyntaxHint("splunk")).toContain("index=");
    expect(getQuerySyntaxHint("elastic")).toContain("query");
    expect(getQuerySyntaxHint("sentinel")).toContain("SecurityAlert");
    expect(getQuerySyntaxHint("qradar")).toContain("SELECT");
  });
});

/* ═══════════════════════════════════════════════════════════
 * Variable Substitution Tests
 * ═══════════════════════════════════════════════════════════ */

describe("Query Variable Substitution", () => {
  it("should substitute single variable", () => {
    const result = substituteQueryVariables(
      "search index=* technique={{technique_id}}",
      { technique_id: "T1190" }
    );
    expect(result).toBe("search index=* technique=T1190");
  });

  it("should substitute multiple variables", () => {
    const result = substituteQueryVariables(
      'index=* technique="{{technique_id}}" earliest=-{{time_range}}h | head {{max_results}}',
      { technique_id: "T1059.001", time_range: "48", max_results: "200" }
    );
    expect(result).toContain("T1059.001");
    expect(result).toContain("-48h");
    expect(result).toContain("head 200");
  });

  it("should substitute all occurrences of the same variable", () => {
    const result = substituteQueryVariables(
      "{{host}} OR dest={{host}}",
      { host: "10.0.1.5" }
    );
    expect(result).toBe("10.0.1.5 OR dest=10.0.1.5");
  });

  it("should leave unmatched variables intact", () => {
    const result = substituteQueryVariables(
      "technique={{technique_id}} host={{host}}",
      { technique_id: "T1190" }
    );
    expect(result).toContain("T1190");
    expect(result).toContain("{{host}}");
  });

  it("should handle empty variables object", () => {
    const query = "search {{technique_id}}";
    const result = substituteQueryVariables(query, {});
    expect(result).toBe(query);
  });
});

/* ═══════════════════════════════════════════════════════════
 * Variable Extraction Tests
 * ═══════════════════════════════════════════════════════════ */

describe("Query Variable Extraction", () => {
  it("should extract variables from query", () => {
    const vars = extractQueryVariables(
      'index=* technique="{{technique_id}}" earliest=-{{time_range}}h | head {{max_results}}'
    );
    expect(vars).toContain("technique_id");
    expect(vars).toContain("time_range");
    expect(vars).toContain("max_results");
    expect(vars.length).toBe(3);
  });

  it("should return unique variables only", () => {
    const vars = extractQueryVariables("{{host}} OR dest={{host}} AND src={{host}}");
    expect(vars).toEqual(["host"]);
  });

  it("should return empty array for queries without variables", () => {
    const vars = extractQueryVariables("search index=* severity=critical");
    expect(vars).toEqual([]);
  });

  it("should handle complex template queries", () => {
    const splunkTemplate = DEFAULT_QUERY_TEMPLATES.find(t => t.id === "splunk-mitre-technique");
    expect(splunkTemplate).toBeDefined();
    const vars = extractQueryVariables(splunkTemplate!.query);
    expect(vars).toContain("technique_id");
    expect(vars).toContain("time_range");
    expect(vars).toContain("max_results");
  });
});

/* ═══════════════════════════════════════════════════════════
 * Template Integration Tests
 * ═══════════════════════════════════════════════════════════ */

describe("Template + Substitution Integration", () => {
  it("should fully resolve a Splunk MITRE technique template", () => {
    const template = getDefaultTemplates("splunk").find(t => t.id === "splunk-mitre-technique");
    expect(template).toBeDefined();
    
    const resolved = substituteQueryVariables(template!.query, {
      technique_id: "T1190",
      time_range: "24",
      max_results: "100",
    });
    
    expect(resolved).toContain("T1190");
    expect(resolved).toContain("-24h");
    expect(resolved).toContain("head 100");
    expect(resolved).not.toContain("{{");
  });

  it("should fully resolve an Elastic high severity template", () => {
    const template = getDefaultTemplates("elastic").find(t => t.id === "elastic-high-severity");
    expect(template).toBeDefined();
    
    const resolved = substituteQueryVariables(template!.query, {
      time_range: "48",
      max_results: "250",
    });
    
    expect(resolved).toContain("now-48h");
    expect(resolved).toContain('"size":250');
    expect(resolved).not.toContain("{{");
  });

  it("should fully resolve a Sentinel template", () => {
    const template = getDefaultTemplates("sentinel").find(t => t.id === "sentinel-high-severity");
    expect(template).toBeDefined();
    
    const resolved = substituteQueryVariables(template!.query, {
      time_range: "72",
      max_results: "50",
    });
    
    expect(resolved).toContain("ago(72h)");
    expect(resolved).toContain("take 50");
    expect(resolved).not.toContain("{{");
  });

  it("should fully resolve a QRadar template", () => {
    const template = getDefaultTemplates("qradar").find(t => t.id === "qradar-high-severity");
    expect(template).toBeDefined();
    
    const resolved = substituteQueryVariables(template!.query, {
      time_range: "12",
      max_results: "500",
    });
    
    expect(resolved).toContain("LAST 12 HOURS");
    expect(resolved).toContain("LIMIT 500");
    expect(resolved).not.toContain("{{");
  });

  it("should identify unresolved variables after partial substitution", () => {
    const template = getDefaultTemplates("splunk").find(t => t.id === "splunk-host-activity");
    expect(template).toBeDefined();
    
    // Only substitute time_range and max_results, leave host unresolved
    const partial = substituteQueryVariables(template!.query, {
      time_range: "24",
      max_results: "100",
    });
    
    const remaining = extractQueryVariables(partial);
    expect(remaining).toContain("host");
    expect(remaining).not.toContain("time_range");
    expect(remaining).not.toContain("max_results");
  });
});
