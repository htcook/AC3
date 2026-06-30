import { describe, it, expect } from "vitest";

describe("AWS DEV Credentials Validation", () => {
  it("should have AWS_DEV_ACCESS_KEY_ID set and properly formatted", () => {
    const key = process.env.AWS_DEV_ACCESS_KEY_ID;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(10);
    expect(key).toMatch(/^ASIA/); // Session-based key starts with ASIA
  });

  it("should have AWS_DEV_SECRET_ACCESS_KEY set", () => {
    const secret = process.env.AWS_DEV_SECRET_ACCESS_KEY;
    expect(secret).toBeDefined();
    expect(secret!.length).toBe(40);
  });

  it("should have AWS_DEV_SESSION_TOKEN set", () => {
    const token = process.env.AWS_DEV_SESSION_TOKEN;
    expect(token).toBeDefined();
    expect(token!.length).toBeGreaterThan(200);
  });
});
