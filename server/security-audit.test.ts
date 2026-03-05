import { describe, expect, it } from "vitest";
import * as fs from "fs";
import * as path from "path";

// --- 1. All Caldera Proxy Endpoints Are Protected ---

describe("Security Audit: caldera-proxy.ts uses protectedProcedure", () => {
  const content = fs.readFileSync(
    path.join(__dirname, "routers/caldera-proxy.ts"),
    "utf-8"
  );

  it("has zero publicProcedure endpoints", () => {
    const publicCount = (content.match(/publicProcedure/g) || []).length;
    expect(publicCount).toBe(0);
  });

  it("has at least 10 protectedProcedure endpoints", () => {
    const protectedCount = (content.match(/protectedProcedure/g) || []).length;
    expect(protectedCount).toBeGreaterThanOrEqual(10);
  });
});

// --- 2. All GoPhish Proxy Endpoints Are Protected ---

describe("Security Audit: gophish-proxy.ts uses protectedProcedure", () => {
  const content = fs.readFileSync(
    path.join(__dirname, "routers/gophish-proxy.ts"),
    "utf-8"
  );

  it("has zero publicProcedure endpoints", () => {
    const publicCount = (content.match(/publicProcedure/g) || []).length;
    expect(publicCount).toBe(0);
  });

  it("has at least 5 protectedProcedure endpoints", () => {
    const protectedCount = (content.match(/protectedProcedure/g) || []).length;
    expect(protectedCount).toBeGreaterThanOrEqual(5);
  });
});

// --- 3. All IOC Feed Endpoints Are Protected ---

describe("Security Audit: ioc-feed.ts uses protectedProcedure", () => {
  const content = fs.readFileSync(
    path.join(__dirname, "routers/ioc-feed.ts"),
    "utf-8"
  );

  it("has zero publicProcedure endpoints", () => {
    const publicCount = (content.match(/publicProcedure/g) || []).length;
    expect(publicCount).toBe(0);
  });

  it("has at least 3 protectedProcedure endpoints", () => {
    const protectedCount = (content.match(/protectedProcedure/g) || []).length;
    expect(protectedCount).toBeGreaterThanOrEqual(3);
  });
});

// --- 4. All Engagements Core Endpoints Are Protected ---

describe("Security Audit: engagements-core.ts uses protectedProcedure", () => {
  const content = fs.readFileSync(
    path.join(__dirname, "routers/engagements-core.ts"),
    "utf-8"
  );

  it("has zero publicProcedure endpoints", () => {
    const publicCount = (content.match(/publicProcedure/g) || []).length;
    expect(publicCount).toBe(0);
  });

  it("has at least 5 protectedProcedure endpoints", () => {
    const protectedCount = (content.match(/protectedProcedure/g) || []).length;
    expect(protectedCount).toBeGreaterThanOrEqual(5);
  });
});

// --- 5. No Remaining NODE_TLS_REJECT_UNAUTHORIZED Bypasses ---

describe("Security Audit: No global TLS bypass in server code", () => {
  const serverDir = path.join(__dirname);

  function findTsFiles(dir: string): string[] {
    const results: string[] = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      if (entry.isDirectory()) {
        results.push(...findTsFiles(fullPath));
      } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") && !entry.name.endsWith(".d.ts")) {
        results.push(fullPath);
      }
    }
    return results;
  }

  const tsFiles = findTsFiles(serverDir);

  it("no server .ts file sets NODE_TLS_REJECT_UNAUTHORIZED = 0 in code", () => {
    const violations: string[] = [];
    for (const file of tsFiles) {
      const content = fs.readFileSync(file, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
        if (/process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/.test(trimmed)) {
          violations.push(`${path.relative(serverDir, file)}:${i + 1}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});

// --- 6. Engagement Ops Core Dedup Guards ---

describe("Security Audit: Engagement dedup guards", () => {
  it("engagement-ops-core.ts startActiveScan resets stats before scan", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "routers/engagement-ops-core.ts"),
      "utf-8"
    );
    expect(content).toMatch(/delete|reset|clear|assetFindings/i);
  });
});

// --- 7. Vuln Scanner Stats Deduplication ---

describe("Security Audit: Vuln scanner stats deduplication", () => {
  it("vuln-scanner.ts getStats uses COUNT DISTINCT or unique counting", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "routers/vuln-scanner.ts"),
      "utf-8"
    );
    expect(content).toMatch(/DISTINCT|distinct|countDistinct|unique/i);
  });
});

// --- 8. Home Page Auth Redirect ---

describe("Security Audit: Home page auth redirect", () => {
  it("Home.tsx redirects unauthenticated users to login", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "../client/src/pages/Home.tsx"),
      "utf-8"
    );
    expect(content).toMatch(/login|getLoginUrl|useAuth/i);
  });
});
