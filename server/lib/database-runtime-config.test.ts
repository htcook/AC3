import { describe, expect, it } from "vitest";
import { resolveDatabaseUrl } from "../../database-runtime-config.mjs";

describe("production database runtime configuration", () => {
  it("keeps an explicitly supplied DATABASE_URL unchanged", () => {
    const databaseUrl = "mysql://user:password@example.internal:3306/ac3plus";
    expect(resolveDatabaseUrl({ DATABASE_URL: databaseUrl })).toBe(databaseUrl);
  });

  it("constructs an encoded MySQL URL from the ECS split RDS variables", () => {
    const resolved = resolveDatabaseUrl({
      DATABASE_HOST: "ac3-production-app-mysql.example.rds.amazonaws.com",
      DATABASE_PORT: "3306",
      DATABASE_USERNAME: "ac3plus_platform_app",
      DATABASE_PASSWORD: "p@ss word:/?#",
      DATABASE_NAME: "ac3plus",
    });

    const url = new URL(resolved!);
    expect(url.protocol).toBe("mysql:");
    expect(url.hostname).toBe("ac3-production-app-mysql.example.rds.amazonaws.com");
    expect(url.port).toBe("3306");
    expect(decodeURIComponent(url.username)).toBe("ac3plus_platform_app");
    expect(decodeURIComponent(url.password)).toBe("p@ss word:/?#");
    expect(url.pathname).toBe("/ac3plus");
  });

  it("returns undefined when no database configuration exists", () => {
    expect(resolveDatabaseUrl({})).toBeUndefined();
  });

  it("fails closed when only part of the split database configuration exists", () => {
    expect(() => resolveDatabaseUrl({
      DATABASE_HOST: "ac3-production-app-mysql.example.rds.amazonaws.com",
      DATABASE_USERNAME: "ac3plus_platform_app",
    })).toThrow(/Incomplete split database configuration/);
  });

  it("rejects an invalid configured database port", () => {
    expect(() => resolveDatabaseUrl({
      DATABASE_HOST: "db.example.internal",
      DATABASE_PORT: "70000",
      DATABASE_USERNAME: "app",
      DATABASE_PASSWORD: "secret",
      DATABASE_NAME: "ac3plus",
    })).toThrow(/DATABASE_PORT/);
  });
});
