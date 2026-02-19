import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

/**
 * Tests for the disabled button styling fix.
 * 
 * Root cause: Tailwind CSS 4 was not generating the `disabled:opacity-50` 
 * and `disabled:pointer-events-none` CSS utility rules, causing disabled 
 * buttons to look identical to enabled buttons (opacity: 1 in both states).
 * 
 * Fix: Added explicit CSS rules in index.css @layer base for 
 * button:disabled, [type="button"]:disabled, etc.
 */

describe("Disabled Button Styling Fix", () => {
  const indexCss = readFileSync(
    join(__dirname, "../client/src/index.css"),
    "utf-8"
  );

  it("should have explicit disabled button CSS rules in index.css", () => {
    expect(indexCss).toContain("button:disabled");
    expect(indexCss).toContain("opacity: 0.5");
    expect(indexCss).toContain("pointer-events: none");
    expect(indexCss).toContain("cursor: not-allowed");
  });

  it("should cover all button type selectors for disabled state", () => {
    expect(indexCss).toContain('[type="button"]:disabled');
    expect(indexCss).toContain('[type="submit"]:disabled');
    expect(indexCss).toContain('[type="reset"]:disabled');
  });

  it("should have the disabled rules inside @layer base", () => {
    // Extract the @layer base block
    const layerBaseMatch = indexCss.match(/@layer base\s*\{([\s\S]*?)(?=\n@|\n\/\*\s*═)/);
    expect(layerBaseMatch).not.toBeNull();
    const layerBaseContent = layerBaseMatch![1];
    expect(layerBaseContent).toContain("button:disabled");
    expect(layerBaseContent).toContain("opacity: 0.5");
  });

  it("should still have the cursor-pointer rules for non-disabled buttons", () => {
    expect(indexCss).toContain("button:not(:disabled)");
    expect(indexCss).toContain("cursor-pointer");
  });
});

describe("Button Component Variant Classes", () => {
  const buttonTsx = readFileSync(
    join(__dirname, "../client/src/components/ui/button.tsx"),
    "utf-8"
  );

  it("should still have disabled: utility classes as fallback", () => {
    // The button component should still include the Tailwind disabled: classes
    // even though they don't work in Tailwind 4 — they serve as documentation
    // and may work in future Tailwind versions
    expect(buttonTsx).toContain("disabled:pointer-events-none");
    expect(buttonTsx).toContain("disabled:opacity-50");
  });
});

describe("Domain Intel Launch Button", () => {
  const domainIntelTsx = readFileSync(
    join(__dirname, "../client/src/pages/DomainIntel.tsx"),
    "utf-8"
  );

  it("should have canLaunch condition requiring domain, customerName, and sector", () => {
    expect(domainIntelTsx).toContain("canLaunch");
    expect(domainIntelTsx).toMatch(/canLaunch.*=.*primaryDomain.*&&.*customerName.*&&.*sector/s);
  });

  it("should disable button when canLaunch is false or scan is pending", () => {
    expect(domainIntelTsx).toMatch(/disabled=\{!canLaunch\s*\|\|\s*startScan\.isPending\}/);
  });

  it("should show helper text when canLaunch is false", () => {
    expect(domainIntelTsx).toContain("Fill in the target domain, organization name, and sector to launch");
  });

  it("should have the launch button with visible purple styling", () => {
    expect(domainIntelTsx).toContain("bg-purple-600");
    expect(domainIntelTsx).toContain("hover:bg-purple-700");
  });
});
