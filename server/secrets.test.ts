import { describe, it, expect } from "vitest";

describe("Environment secrets validation", () => {
  it("should have CALDERA_BASE_URL set", () => {
    const val = process.env.CALDERA_BASE_URL;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(0);
    expect(val).toContain("://");
  });

  it("should have CALDERA_API_KEY set", () => {
    const val = process.env.CALDERA_API_KEY;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(0);
  });

  it("should have CALDERA_USERNAME set", () => {
    const val = process.env.CALDERA_USERNAME;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(0);
  });

  it("should have CALDERA_PASSWORD set", () => {
    const val = process.env.CALDERA_PASSWORD;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(5);
  });

  it("should have GOPHISH_API_KEY set", () => {
    const val = process.env.GOPHISH_API_KEY;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(10);
  });

  it("should have GOPHISH_BASE_URL set", () => {
    const val = process.env.GOPHISH_BASE_URL;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(0);
    expect(val).toContain("://");
  });

  it("ENV module should load secrets correctly", async () => {
    const { ENV } = await import("./_core/env");
    expect(ENV.calderaBaseUrl).toBeTruthy();
    expect(ENV.calderaApiKey).toBeTruthy();
    expect(ENV.calderaUsername).toBeTruthy();
    expect(ENV.calderaPassword).toBeTruthy();
    expect(ENV.gophishBaseUrl).toBeTruthy();
    expect(ENV.gophishApiKey).toBeTruthy();
  });
});
