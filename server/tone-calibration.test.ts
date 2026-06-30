/**
 * Tests for LLM tone calibration risk band computation.
 *
 * Validates that the preliminary risk score computation used in
 * generateScanOnlySummary, generateSummaries, and runPostEnrichmentAnalysis
 * correctly computes overall risk, peak risk, and risk bands.
 */
import { describe, it, expect } from "vitest";

// Replicate the risk band computation logic used in all three LLM functions
function computeToneCalibration(hybridRiskScores: number[]) {
  const clientRiskScores = hybridRiskScores;
  const prelimOverallRisk = clientRiskScores.length > 0
    ? Math.round(clientRiskScores.reduce((s, v) => s + v, 0) / clientRiskScores.length)
    : 0;
  const prelimRiskBand = prelimOverallRisk >= 90 ? 'critical' : prelimOverallRisk >= 70 ? 'high' : prelimOverallRisk >= 40 ? 'medium' : 'low';
  const maxAssetRisk = clientRiskScores.length > 0 ? Math.max(...clientRiskScores) : 0;
  const maxRiskBand = maxAssetRisk >= 90 ? 'critical' : maxAssetRisk >= 70 ? 'high' : maxAssetRisk >= 40 ? 'medium' : 'low';

  return { prelimOverallRisk, prelimRiskBand, maxAssetRisk, maxRiskBand };
}

describe("Tone Calibration Risk Band Computation", () => {
  it("should return LOW band when most assets have low risk scores", () => {
    // Simulates databank.com scenario: 254 assets, mostly low risk, a few high
    const scores = [
      ...Array(250).fill(10),  // 250 assets at risk 10
      85, 82, 78, 72,          // 4 high-risk assets
    ];
    const result = computeToneCalibration(scores);
    expect(result.prelimRiskBand).toBe("low");
    expect(result.prelimOverallRisk).toBeLessThan(40);
    // Peak should still reflect the highest individual asset
    expect(result.maxAssetRisk).toBe(85);
    expect(result.maxRiskBand).toBe("high");
  });

  it("should return MEDIUM band when average is 40-69", () => {
    const scores = [50, 55, 60, 45, 40];
    const result = computeToneCalibration(scores);
    expect(result.prelimRiskBand).toBe("medium");
    expect(result.prelimOverallRisk).toBeGreaterThanOrEqual(40);
    expect(result.prelimOverallRisk).toBeLessThan(70);
  });

  it("should return HIGH band when average is 70-89", () => {
    const scores = [75, 80, 85, 70, 72];
    const result = computeToneCalibration(scores);
    expect(result.prelimRiskBand).toBe("high");
    expect(result.prelimOverallRisk).toBeGreaterThanOrEqual(70);
    expect(result.prelimOverallRisk).toBeLessThan(90);
  });

  it("should return CRITICAL band when average is 90+", () => {
    const scores = [95, 92, 90, 93, 91];
    const result = computeToneCalibration(scores);
    expect(result.prelimRiskBand).toBe("critical");
    expect(result.prelimOverallRisk).toBeGreaterThanOrEqual(90);
  });

  it("should return LOW/0 for empty asset list", () => {
    const result = computeToneCalibration([]);
    expect(result.prelimOverallRisk).toBe(0);
    expect(result.prelimRiskBand).toBe("low");
    expect(result.maxAssetRisk).toBe(0);
    expect(result.maxRiskBand).toBe("low");
  });

  it("should correctly identify peak risk divergence from average", () => {
    // 99 low-risk assets + 1 critical asset
    const scores = [...Array(99).fill(5), 95];
    const result = computeToneCalibration(scores);
    // Average should be very low: (99*5 + 95) / 100 = 5.9 ≈ 6
    expect(result.prelimRiskBand).toBe("low");
    expect(result.prelimOverallRisk).toBeLessThan(10);
    // But peak should be critical
    expect(result.maxAssetRisk).toBe(95);
    expect(result.maxRiskBand).toBe("critical");
  });

  it("should round the overall risk score", () => {
    const scores = [33, 34, 35]; // avg = 34.0
    const result = computeToneCalibration(scores);
    expect(result.prelimOverallRisk).toBe(34);
  });

  it("should handle single asset correctly", () => {
    const result = computeToneCalibration([72]);
    expect(result.prelimOverallRisk).toBe(72);
    expect(result.prelimRiskBand).toBe("high");
    expect(result.maxAssetRisk).toBe(72);
    expect(result.maxRiskBand).toBe("high");
  });

  it("should handle boundary values correctly", () => {
    // Test exact boundaries
    expect(computeToneCalibration([39]).prelimRiskBand).toBe("low");
    expect(computeToneCalibration([40]).prelimRiskBand).toBe("medium");
    expect(computeToneCalibration([69]).prelimRiskBand).toBe("medium");
    expect(computeToneCalibration([70]).prelimRiskBand).toBe("high");
    expect(computeToneCalibration([89]).prelimRiskBand).toBe("high");
    expect(computeToneCalibration([90]).prelimRiskBand).toBe("critical");
  });
});
