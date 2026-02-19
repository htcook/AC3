import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

const CLIENT_DIR = join(__dirname, "..", "client", "src");
const PAGES_DIR = join(CLIENT_DIR, "pages");
const COMPONENTS_DIR = join(CLIENT_DIR, "components");

/**
 * Mobile-Responsive Operations View Tests
 * Enhancement #2: Ensures all key pages and components have proper mobile responsiveness
 */

// ─── Global CSS Tests ─────────────────────────────────────────────────────────

describe("Global Mobile CSS", () => {
  const cssContent = readFileSync(join(CLIENT_DIR, "index.css"), "utf-8");

  it("should have mobile breakpoint media query (max-width: 767px)", () => {
    expect(cssContent).toContain("@media (max-width: 767px)");
  });

  it("should have tablet breakpoint media query", () => {
    expect(cssContent).toContain("@media (min-width: 768px) and (max-width: 1023px)");
  });

  it("should have small screen breakpoint (max-width: 639px)", () => {
    expect(cssContent).toContain("@media (max-width: 639px)");
  });

  it("should make tables horizontally scrollable on mobile", () => {
    expect(cssContent).toContain("overflow-x: auto");
    expect(cssContent).toContain("-webkit-overflow-scrolling: touch");
  });

  it("should stack grid columns on mobile", () => {
    expect(cssContent).toContain("grid-template-columns: 1fr !important");
  });

  it("should reduce heading sizes on mobile", () => {
    expect(cssContent).toMatch(/h1\s*\{[\s\S]*?font-size:\s*1\.25rem/);
  });

  it("should make dialogs full-width on mobile", () => {
    expect(cssContent).toContain('width: 95vw !important');
  });

  it("should reduce padding on cards for small screens", () => {
    expect(cssContent).toMatch(/\.p-6\s*\{[\s\S]*?padding:\s*1rem/);
  });
});

// ─── MobileTableWrapper Component Tests ───────────────────────────────────────

describe("MobileTableWrapper Component", () => {
  const componentPath = join(COMPONENTS_DIR, "MobileTableWrapper.tsx");

  it("should exist", () => {
    expect(existsSync(componentPath)).toBe(true);
  });

  it("should export MobileTableWrapper component", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("export function MobileTableWrapper");
  });

  it("should export MobileStatGrid component", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("export function MobileStatGrid");
  });

  it("should export MobileFilterBar component", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("export function MobileFilterBar");
  });

  it("should export MobilePageHeader component", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("export function MobilePageHeader");
  });

  it("should export MobileCardView component", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("export function MobileCardView");
  });

  it("should use overflow-x-auto for horizontal scrolling", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("overflow-x-auto");
  });

  it("should have responsive grid classes in MobileStatGrid", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("grid-cols-2");
    expect(content).toContain("sm:grid-cols-3");
  });

  it("should stack header vertically on mobile in MobilePageHeader", () => {
    const content = readFileSync(componentPath, "utf-8");
    expect(content).toContain("flex-col sm:flex-row");
  });
});

// ─── useIsMobile Hook Tests ───────────────────────────────────────────────────

describe("useIsMobile Hook", () => {
  const hookPath = join(CLIENT_DIR, "hooks", "useIsMobile.ts");

  it("should exist", () => {
    expect(existsSync(hookPath)).toBe(true);
  });

  it("should export useIsMobile hook", () => {
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("export function useIsMobile");
  });

  it("should export useBreakpoint hook", () => {
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("export function useBreakpoint");
  });

  it("should have debounced resize handler", () => {
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("setTimeout");
    expect(content).toContain("clearTimeout");
  });

  it("should support custom breakpoint parameter", () => {
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("breakpoint: number = 768");
  });

  it("should define all Tailwind breakpoint sizes", () => {
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("640");
    expect(content).toContain("768");
    expect(content).toContain("1024");
    expect(content).toContain("1280");
    expect(content).toContain("1536");
  });
});

// ─── AppShell Mobile Foundation Tests ─────────────────────────────────────────

describe("AppShell Mobile Foundations", () => {
  const appShellContent = readFileSync(join(COMPONENTS_DIR, "AppShell.tsx"), "utf-8");

  it("should have mobile sidebar overlay with backdrop", () => {
    expect(appShellContent).toContain("fixed inset-0 bg-black/60");
    expect(appShellContent).toContain("lg:hidden");
  });

  it("should have hamburger menu button", () => {
    expect(appShellContent).toContain("Open navigation");
    expect(appShellContent).toContain("Menu");
  });

  it("should have close button for mobile sidebar", () => {
    expect(appShellContent).toContain("Close navigation");
  });

  it("should prevent body scroll when sidebar is open", () => {
    expect(appShellContent).toContain('document.body.style.overflow = "hidden"');
  });

  it("should have touch-friendly 44px tap targets", () => {
    expect(appShellContent).toContain("min-h-[44px]");
    expect(appShellContent).toContain("min-w-[44px]");
  });

  it("should have responsive content padding", () => {
    expect(appShellContent).toContain('p-4 sm:p-6 lg:p-8');
  });

  it("should have sticky mobile header bar", () => {
    expect(appShellContent).toContain("sticky top-0");
    expect(appShellContent).toContain("lg:hidden");
  });

  it("should close sidebar on escape key", () => {
    expect(appShellContent).toContain("Escape");
  });

  it("should have sidebar transform transition for smooth open/close", () => {
    expect(appShellContent).toContain("transition-transform");
    expect(appShellContent).toContain("-translate-x-full");
  });
});

// ─── Key Page Responsive Patterns ─────────────────────────────────────────────

describe("Dashboard Page Responsiveness", () => {
  const dashboardContent = readFileSync(join(PAGES_DIR, "Dashboard.tsx"), "utf-8");

  it("should have responsive grid breakpoints", () => {
    expect(dashboardContent).toContain("sm:grid-cols");
  });

  it("should have responsive text sizing", () => {
    expect(dashboardContent).toMatch(/sm:text-|lg:text-/);
  });

  it("should have responsive gap sizing", () => {
    expect(dashboardContent).toMatch(/sm:gap-|lg:gap-/);
  });
});

describe("Engagements Page Responsiveness", () => {
  const engagementsContent = readFileSync(join(PAGES_DIR, "Engagements.tsx"), "utf-8");

  it("should have responsive header layout (stacks on mobile)", () => {
    expect(engagementsContent).toContain("flex-col sm:flex-row");
  });

  it("should have responsive stat grid", () => {
    expect(engagementsContent).toContain("grid-cols-2 sm:grid-cols-3 lg:grid-cols-5");
  });

  it("should have responsive engagement card layout", () => {
    expect(engagementsContent).toContain("flex flex-col sm:flex-row sm:items-start");
  });

  it("should have responsive action buttons with flex-wrap", () => {
    expect(engagementsContent).toContain("flex-wrap");
  });

  it("should have responsive text sizing in metadata", () => {
    expect(engagementsContent).toContain("text-xs sm:text-sm");
  });

  it("should have responsive gap in bulk actions bar", () => {
    expect(engagementsContent).toContain("gap-2 sm:gap-3");
  });
});

describe("PhishingOperations Page Responsiveness", () => {
  const phishingContent = readFileSync(join(PAGES_DIR, "PhishingOperations.tsx"), "utf-8");

  it("should have responsive stat grid", () => {
    expect(phishingContent).toContain("sm:grid-cols-3");
  });

  it("should have responsive filter bar", () => {
    expect(phishingContent).toContain("flex-col sm:flex-row");
  });

  it("should have responsive draft detail header", () => {
    expect(phishingContent).toContain("flex flex-col sm:flex-row sm:items-center sm:justify-between");
  });
});

describe("IOCFeed Page Responsiveness", () => {
  const iocContent = readFileSync(join(PAGES_DIR, "IOCFeed.tsx"), "utf-8");

  it("should have responsive stat grid with sm breakpoint", () => {
    expect(iocContent).toContain("sm:grid-cols-2");
  });

  it("should have responsive page header", () => {
    expect(iocContent).toContain("flex-col sm:flex-row");
  });
});

describe("AbilitiesLibrary Page Responsiveness", () => {
  const abilitiesContent = readFileSync(join(PAGES_DIR, "AbilitiesLibrary.tsx"), "utf-8");

  it("should have responsive stat grid with sm breakpoint", () => {
    expect(abilitiesContent).toContain("sm:grid-cols-3");
  });

  it("should have responsive card grid", () => {
    expect(abilitiesContent).toContain("sm:grid-cols-2 lg:grid-cols-3");
  });
});

describe("TtpKnowledge Page Responsiveness", () => {
  const ttpContent = readFileSync(join(PAGES_DIR, "TtpKnowledge.tsx"), "utf-8");

  it("should have responsive stat grid", () => {
    expect(ttpContent).toContain("sm:grid-cols-2 md:grid-cols-4");
  });

  it("should have responsive page header", () => {
    expect(ttpContent).toContain("flex-col sm:flex-row");
  });
});

describe("KevDashboard Page Responsiveness", () => {
  const kevContent = readFileSync(join(PAGES_DIR, "KevDashboard.tsx"), "utf-8");

  it("should have responsive stat grid with sm breakpoint", () => {
    expect(kevContent).toContain("sm:grid-cols-3");
  });

  it("should have responsive page header", () => {
    expect(kevContent).toContain("flex-col sm:flex-row");
  });
});

describe("ThreatIntelHub Page Responsiveness", () => {
  const threatContent = readFileSync(join(PAGES_DIR, "ThreatIntelHub.tsx"), "utf-8");

  it("should have responsive stat grid with sm breakpoint", () => {
    expect(threatContent).toContain("sm:grid-cols-3");
  });

  it("should have responsive page header", () => {
    expect(threatContent).toContain("flex-col sm:flex-row");
  });
});

describe("AgentDeploy Page Responsiveness", () => {
  const agentContent = readFileSync(join(PAGES_DIR, "AgentDeploy.tsx"), "utf-8");

  it("should have responsive grid with sm breakpoint", () => {
    expect(agentContent).toContain("sm:grid-cols-2");
  });
});
