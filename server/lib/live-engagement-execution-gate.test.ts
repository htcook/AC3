import { describe, expect, it } from "vitest";
import { isLiveEngagementExecutionEnabled } from "./live-engagement-execution-gate";

describe("isLiveEngagementExecutionEnabled", () => {
  it.each([undefined, "", "false", "TRUE", " true", "1", "yes"])
    ("fails closed for %j", (value) => {
      expect(isLiveEngagementExecutionEnabled(value)).toBe(false);
    });

  it("accepts only the explicit literal true", () => {
    expect(isLiveEngagementExecutionEnabled("true")).toBe(true);
  });
});
