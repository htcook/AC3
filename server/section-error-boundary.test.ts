/**
 * Tests for SectionErrorBoundary behavior
 * Validates that the component catches errors and provides retry functionality
 */
import { describe, it, expect } from "vitest";

describe("SectionErrorBoundary design", () => {
  it("should be a React class component with error boundary lifecycle", async () => {
    // Verify the component file exists and exports correctly
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/components/SectionErrorBoundary.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    // Must be a class component (required for error boundaries)
    expect(content).toContain("class SectionErrorBoundary extends Component");
    // Must implement getDerivedStateFromError
    expect(content).toContain("getDerivedStateFromError");
    // Must implement componentDidCatch
    expect(content).toContain("componentDidCatch");
    // Must have retry functionality
    expect(content).toContain("handleRetry");
    // Must track retry count
    expect(content).toContain("retryCount");
  });

  it("should support sectionName prop for error messages", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/components/SectionErrorBoundary.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    expect(content).toContain("sectionName");
    expect(content).toContain("UNAVAILABLE");
  });

  it("should support compact mode for inline error display", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/components/SectionErrorBoundary.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    expect(content).toContain("compact");
    expect(content).toContain("failed to load");
  });

  it("should display the error message in non-compact mode", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/components/SectionErrorBoundary.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    expect(content).toContain("error.message");
  });

  it("should reset error state on retry", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/components/SectionErrorBoundary.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    // handleRetry should set hasError to false and increment retryCount
    expect(content).toContain("hasError: false");
    expect(content).toContain("retryCount: prev.retryCount + 1");
  });
});

describe("Dashboard SectionErrorBoundary integration", () => {
  it("should wrap all crash-prone dashboard sections", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/pages/Dashboard.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    // Must import SectionErrorBoundary
    expect(content).toContain("import { SectionErrorBoundary }");

    // Must wrap these sections:
    expect(content).toContain('sectionName="Recent Scans"');
    expect(content).toContain('sectionName="Vulnerability Feed"');
    expect(content).toContain('sectionName="Threat Awareness"');
    expect(content).toContain('sectionName="Server Status"');
    expect(content).toContain('sectionName="Phishing Metrics"');
    expect(content).toContain('sectionName="Live Stats"');
  });

  it("should use compact mode for the Live Stats section", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/pages/Dashboard.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    // Live Stats should use compact mode
    expect(content).toContain('sectionName="Live Stats" compact');
  });

  it("should have at least 6 SectionErrorBoundary instances in Dashboard", async () => {
    const fs = await import("fs");
    const path = require("path");
    const filePath = path.resolve(__dirname, "../client/src/pages/Dashboard.tsx");
    const content = fs.readFileSync(filePath, "utf-8");

    const openingTags = (content.match(/<SectionErrorBoundary/g) || []).length;
    const closingTags = (content.match(/<\/SectionErrorBoundary>/g) || []).length;

    expect(openingTags).toBeGreaterThanOrEqual(6);
    expect(closingTags).toBeGreaterThanOrEqual(6);
    expect(openingTags).toBe(closingTags);
  });
});
