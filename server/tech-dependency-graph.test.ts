/**
 * Tests for Tech Dependency Graph — data model and graph building logic.
 * Tests the dependency relationship definitions and graph construction from detected technologies.
 */
import { describe, it, expect } from "vitest";

// We test the shared lib logic — import from client/src/lib
// These are pure functions with no React dependencies
import {
  TECH_DEPENDENCIES,
  CATEGORY_COLORS,
  CATEGORY_LABELS,
  buildTechDepGraph,
  type TechDepNode,
  type TechDepEdge,
  type TechDepGraph,
  type TechCategory,
} from "../client/src/lib/tech-dependency-graph";

describe("Tech Dependency Graph — Data Model", () => {
  describe("TECH_DEPENDENCIES", () => {
    it("should contain at least 80 technology entries", () => {
      expect(TECH_DEPENDENCIES.length).toBeGreaterThanOrEqual(80);
    });

    it("should have unique technology names", () => {
      const names = TECH_DEPENDENCIES.map(d => d.name.toLowerCase());
      const uniqueNames = new Set(names);
      expect(uniqueNames.size).toBe(names.length);
    });

    it("should have valid categories for all entries", () => {
      const validCategories = Object.keys(CATEGORY_COLORS);
      for (const dep of TECH_DEPENDENCIES) {
        expect(validCategories).toContain(dep.category);
      }
    });

    it("should have all dependsOn references pointing to existing technologies", () => {
      const nameSet = new Set(TECH_DEPENDENCIES.map(d => d.name));
      for (const dep of TECH_DEPENDENCIES) {
        for (const parent of dep.dependsOn) {
          expect(nameSet.has(parent)).toBe(true);
        }
      }
    });

    it("should include core web technologies", () => {
      const names = TECH_DEPENDENCIES.map(d => d.name.toLowerCase());
      expect(names).toContain("javascript");
      expect(names).toContain("php");
      expect(names).toContain("python");
      expect(names).toContain("mysql");
      expect(names).toContain("nginx");
      expect(names).toContain("apache");
    });

    it("should define jQuery as depending on JavaScript", () => {
      const jquery = TECH_DEPENDENCIES.find(d => d.name === "jQuery");
      expect(jquery).toBeDefined();
      expect(jquery!.dependsOn).toContain("JavaScript");
      expect(jquery!.category).toBe("library");
    });

    it("should define WordPress as depending on PHP and MySQL", () => {
      const wp = TECH_DEPENDENCIES.find(d => d.name === "WordPress");
      expect(wp).toBeDefined();
      expect(wp!.dependsOn).toContain("PHP");
      expect(wp!.dependsOn).toContain("MySQL");
      expect(wp!.category).toBe("cms");
    });

    it("should define Next.js as depending on React", () => {
      const next = TECH_DEPENDENCIES.find(d => d.name === "Next.js");
      expect(next).toBeDefined();
      expect(next!.dependsOn).toContain("React");
    });

    it("should define Angular as depending on TypeScript", () => {
      const angular = TECH_DEPENDENCIES.find(d => d.name === "Angular");
      expect(angular).toBeDefined();
      expect(angular!.dependsOn).toContain("TypeScript");
    });

    it("should define TypeScript as depending on JavaScript", () => {
      const ts = TECH_DEPENDENCIES.find(d => d.name === "TypeScript");
      expect(ts).toBeDefined();
      expect(ts!.dependsOn).toContain("JavaScript");
    });

    it("should define Kubernetes as depending on Docker", () => {
      const k8s = TECH_DEPENDENCIES.find(d => d.name === "Kubernetes");
      expect(k8s).toBeDefined();
      expect(k8s!.dependsOn).toContain("Docker");
    });

    it("should have no circular dependencies (depth 3)", () => {
      const depMap = new Map(TECH_DEPENDENCIES.map(d => [d.name, d.dependsOn]));
      for (const dep of TECH_DEPENDENCIES) {
        const visited = new Set<string>();
        const stack = [...dep.dependsOn];
        let depth = 0;
        while (stack.length > 0 && depth < 3) {
          const current = stack.shift()!;
          if (current === dep.name) {
            throw new Error(`Circular dependency detected: ${dep.name}`);
          }
          if (!visited.has(current)) {
            visited.add(current);
            const parents = depMap.get(current) || [];
            stack.push(...parents);
          }
          depth++;
        }
      }
    });
  });

  describe("CATEGORY_COLORS", () => {
    it("should have colors for all categories", () => {
      const categories: TechCategory[] = [
        "language", "framework", "cms", "database", "server",
        "cdn", "analytics", "security", "cloud", "library",
        "build_tool", "other",
      ];
      for (const cat of categories) {
        expect(CATEGORY_COLORS[cat]).toBeDefined();
        expect(CATEGORY_COLORS[cat]).toMatch(/^#[0-9A-Fa-f]{6}$/);
      }
    });
  });

  describe("CATEGORY_LABELS", () => {
    it("should have labels for all categories", () => {
      const categories: TechCategory[] = [
        "language", "framework", "cms", "database", "server",
        "cdn", "analytics", "security", "cloud", "library",
        "build_tool", "other",
      ];
      for (const cat of categories) {
        expect(CATEGORY_LABELS[cat]).toBeDefined();
        expect(typeof CATEGORY_LABELS[cat]).toBe("string");
        expect(CATEGORY_LABELS[cat].length).toBeGreaterThan(0);
      }
    });
  });
});

describe("Tech Dependency Graph — buildTechDepGraph()", () => {
  it("should return empty graph for no detected technologies", () => {
    const graph = buildTechDepGraph([]);
    expect(graph.nodes).toHaveLength(0);
    expect(graph.edges).toHaveLength(0);
    expect(graph.categories).toHaveLength(0);
  });

  it("should include detected technology as a node", () => {
    const graph = buildTechDepGraph([{ name: "jQuery", count: 3 }]);
    const jqueryNode = graph.nodes.find(n => n.name === "jQuery");
    expect(jqueryNode).toBeDefined();
    expect(jqueryNode!.detected).toBe(true);
    expect(jqueryNode!.assetCount).toBe(3);
    expect(jqueryNode!.category).toBe("library");
  });

  it("should include dependency chain (jQuery → JavaScript)", () => {
    const graph = buildTechDepGraph([{ name: "jQuery", count: 2 }]);
    const jsNode = graph.nodes.find(n => n.name === "JavaScript");
    expect(jsNode).toBeDefined();
    expect(jsNode!.detected).toBe(false); // Not directly detected
    expect(jsNode!.assetCount).toBe(0);

    // Should have an edge from jQuery to JavaScript
    const jqueryId = graph.nodes.find(n => n.name === "jQuery")!.id;
    const jsId = jsNode!.id;
    const edge = graph.edges.find(e => e.source === jqueryId && e.target === jsId);
    expect(edge).toBeDefined();
    expect(edge!.type).toBe("depends_on");
  });

  it("should include deep dependency chain (Next.js → React → JavaScript)", () => {
    const graph = buildTechDepGraph([{ name: "Next.js", count: 1 }]);
    const reactNode = graph.nodes.find(n => n.name === "React");
    const jsNode = graph.nodes.find(n => n.name === "JavaScript");
    expect(reactNode).toBeDefined();
    expect(jsNode).toBeDefined();
  });

  it("should include WordPress dependencies (PHP and MySQL)", () => {
    const graph = buildTechDepGraph([{ name: "WordPress", count: 5 }]);
    const phpNode = graph.nodes.find(n => n.name === "PHP");
    const mysqlNode = graph.nodes.find(n => n.name === "MySQL");
    expect(phpNode).toBeDefined();
    expect(mysqlNode).toBeDefined();

    const wpId = graph.nodes.find(n => n.name === "WordPress")!.id;
    const phpEdge = graph.edges.find(e => e.source === wpId && e.target === phpNode!.id);
    const mysqlEdge = graph.edges.find(e => e.source === wpId && e.target === mysqlNode!.id);
    expect(phpEdge).toBeDefined();
    expect(mysqlEdge).toBeDefined();
  });

  it("should handle multiple detected technologies with shared dependencies", () => {
    const graph = buildTechDepGraph([
      { name: "React", count: 3 },
      { name: "Vue.js", count: 2 },
    ]);
    // Both depend on JavaScript — should have one JS node
    const jsNodes = graph.nodes.filter(n => n.name === "JavaScript");
    expect(jsNodes).toHaveLength(1);

    // Should have edges from both React and Vue to JavaScript
    const jsId = jsNodes[0].id;
    const reactId = graph.nodes.find(n => n.name === "React")!.id;
    const vueId = graph.nodes.find(n => n.name === "Vue.js")!.id;
    expect(graph.edges.find(e => e.source === reactId && e.target === jsId)).toBeDefined();
    expect(graph.edges.find(e => e.source === vueId && e.target === jsId)).toBeDefined();
  });

  it("should track version information", () => {
    const graph = buildTechDepGraph([
      { name: "jQuery", count: 2, version: "3.6.0" },
    ]);
    const jqueryNode = graph.nodes.find(n => n.name === "jQuery");
    expect(jqueryNode!.version).toBe("3.6.0");
  });

  it("should track outdated status", () => {
    const graph = buildTechDepGraph([
      { name: "jQuery", count: 2, version: "1.8.0", isOutdated: true },
    ]);
    const jqueryNode = graph.nodes.find(n => n.name === "jQuery");
    expect(jqueryNode!.isOutdated).toBe(true);
  });

  it("should compute category counts for detected technologies only", () => {
    const graph = buildTechDepGraph([
      { name: "React", count: 3 },
      { name: "Vue.js", count: 2 },
      { name: "MySQL", count: 1 },
    ]);
    const frameworkCat = graph.categories.find(c => c.category === "framework");
    const dbCat = graph.categories.find(c => c.category === "database");
    expect(frameworkCat).toBeDefined();
    expect(frameworkCat!.count).toBe(2); // React + Vue.js
    expect(dbCat).toBeDefined();
    expect(dbCat!.count).toBe(1); // MySQL
    // JavaScript is a dependency, not detected — should not appear in categories
    const langCat = graph.categories.find(c => c.category === "language");
    expect(langCat).toBeUndefined();
  });

  it("should handle unknown technologies gracefully", () => {
    const graph = buildTechDepGraph([
      { name: "SomeObscureTech", count: 1 },
    ]);
    // Should still create a node for it
    const node = graph.nodes.find(n => n.name === "SomeObscureTech");
    expect(node).toBeDefined();
    expect(node!.detected).toBe(true);
    expect(node!.category).toBe("other");
  });

  it("should generate unique node IDs", () => {
    const graph = buildTechDepGraph([
      { name: "React", count: 1 },
      { name: "Vue.js", count: 1 },
      { name: "Angular", count: 1 },
      { name: "WordPress", count: 1 },
    ]);
    const ids = graph.nodes.map(n => n.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("should sort categories by count descending", () => {
    const graph = buildTechDepGraph([
      { name: "React", count: 5 },
      { name: "Vue.js", count: 3 },
      { name: "Angular", count: 2 },
      { name: "MySQL", count: 10 },
      { name: "PostgreSQL", count: 8 },
    ]);
    for (let i = 1; i < graph.categories.length; i++) {
      expect(graph.categories[i - 1].count).toBeGreaterThanOrEqual(graph.categories[i].count);
    }
  });

  it("should handle case-insensitive technology matching", () => {
    const graph = buildTechDepGraph([
      { name: "jquery", count: 2 },
    ]);
    const jqueryNode = graph.nodes.find(n => n.name === "jQuery");
    expect(jqueryNode).toBeDefined();
    expect(jqueryNode!.detected).toBe(true);
  });

  it("should not create duplicate edges", () => {
    const graph = buildTechDepGraph([
      { name: "WordPress", count: 1 },
    ]);
    const wpId = graph.nodes.find(n => n.name === "WordPress")!.id;
    const phpId = graph.nodes.find(n => n.name === "PHP")!.id;
    const phpEdges = graph.edges.filter(e => e.source === wpId && e.target === phpId);
    expect(phpEdges).toHaveLength(1);
  });

  it("should handle a large realistic tech stack", () => {
    const graph = buildTechDepGraph([
      { name: "Nginx", count: 10 },
      { name: "WordPress", count: 8 },
      { name: "jQuery", count: 15 },
      { name: "Google Analytics", count: 12 },
      { name: "Cloudflare", count: 10 },
      { name: "React", count: 3 },
      { name: "Bootstrap", count: 7 },
      { name: "MySQL", count: 8 },
      { name: "PHP", count: 8 },
      { name: "Let's Encrypt", count: 9 },
    ]);
    expect(graph.nodes.length).toBeGreaterThan(10); // Detected + dependencies
    expect(graph.edges.length).toBeGreaterThan(5);
    expect(graph.categories.length).toBeGreaterThan(3);

    // JavaScript should be pulled in as a dependency
    const jsNode = graph.nodes.find(n => n.name === "JavaScript");
    expect(jsNode).toBeDefined();
  });

  it("should mark implied edges for non-detected dependency nodes", () => {
    const graph = buildTechDepGraph([
      { name: "jQuery", count: 2 },
    ]);
    // jQuery is detected, JavaScript is not — edge type should be "depends_on"
    const jqueryId = graph.nodes.find(n => n.name === "jQuery")!.id;
    const jsId = graph.nodes.find(n => n.name === "JavaScript")!.id;
    const edge = graph.edges.find(e => e.source === jqueryId && e.target === jsId);
    expect(edge).toBeDefined();
    expect(edge!.type).toBe("depends_on");
  });
});
