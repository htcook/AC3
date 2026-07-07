import { describe, it, expect } from "vitest";

describe("White Label Config", () => {
  it("WL_PLATFORM_NAME should be set to AC3", () => {
    expect(process.env.WL_PLATFORM_NAME).toBe("AC3");
  });
});
