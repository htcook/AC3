/**
 * Knowledge Base Router Tests
 *
 * Tests the tRPC procedures that power the Knowledge Base admin page.
 */

import { describe, it, expect } from "vitest";

// We test the underlying functions directly since the router just wraps them
import {
  getLOTLContext,
  getFileUploadBypassContext,
  getFirewallEvasionContext,
  getSocialEngineeringContext,
  getShodanReconContext,
  getSubdomainEnumContext,
  buildOffensiveTechniquesContext,
} from "./lib/knowledge/offensive-techniques-knowledge";
import {
  getGoPhishTemplatesContext,
  getPretextScriptsContext,
  getLandingPagePatternsContext,
  buildPhishingKnowledgeContext,
  GOPHISH_TEMPLATES,
  PRETEXT_SCRIPTS,
  LANDING_PAGE_PATTERNS,
  SOCIAL_ENGINEERING_TEMPLATES_METADATA,
} from "./lib/knowledge/social-engineering-templates";

// ─── Module Registry Tests (via router logic) ──────────────────────────────

describe("Knowledge Base Module Registry", () => {
  // Import the router to test the registry function indirectly
  // We'll test the data shapes that the router returns

  it("all knowledge context builders return non-empty strings", () => {
    const builders = [
      () => getLOTLContext("linux"),
      () => getLOTLContext("windows"),
      () => getLOTLContext("macos"),
      () => getFileUploadBypassContext(),
      () => getFirewallEvasionContext(true, false),
      () => getFirewallEvasionContext(false, true),
      () => getSocialEngineeringContext(),
      () => getShodanReconContext(),
      () => getSubdomainEnumContext(),
      () => getGoPhishTemplatesContext(),
      () => getPretextScriptsContext(),
      () => getLandingPagePatternsContext(),
    ];

    for (const builder of builders) {
      const result = builder();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(50);
      expect(result).not.toContain("undefined");
    }
  });
});

// ─── Phase Context Composition Tests ────────────────────────────────────────

describe("Phase Context Composition", () => {
  const phases = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploitation"] as const;

  it("all phases produce valid context", () => {
    for (const phase of phases) {
      const ctx = buildOffensiveTechniquesContext({
        phase,
        hasFirewall: true,
        hasWAF: true,
        hasFileUpload: true,
        platform: "linux",
      });
      expect(typeof ctx).toBe("string");
      expect(ctx.length).toBeGreaterThan(0);
    }
  });

  it("recon phase includes subdomain and shodan context", () => {
    const ctx = buildOffensiveTechniquesContext({ phase: "recon" });
    expect(ctx).toMatch(/subdomain|Shodan/i);
  });

  it("exploitation phase includes LOTL context", () => {
    const ctx = buildOffensiveTechniquesContext({ phase: "exploitation", platform: "linux" });
    expect(ctx).toContain("GTFOBins");
  });

  it("platform filtering works correctly", () => {
    const linuxCtx = buildOffensiveTechniquesContext({ phase: "exploitation", platform: "linux" });
    const windowsCtx = buildOffensiveTechniquesContext({ phase: "exploitation", platform: "windows" });
    const macCtx = buildOffensiveTechniquesContext({ phase: "exploitation", platform: "macos" });

    expect(linuxCtx).toContain("GTFOBins");
    expect(linuxCtx).not.toContain("LOLBAS");

    expect(windowsCtx).toContain("LOLBAS");
    expect(windowsCtx).not.toContain("GTFOBins");

    expect(macCtx).toContain("LOOBins");
    expect(macCtx).not.toContain("LOLBAS");
  });

  it("conditional modules respect flags", () => {
    const withFirewall = buildOffensiveTechniquesContext({
      phase: "enumeration",
      hasFirewall: true,
    });
    const withoutFirewall = buildOffensiveTechniquesContext({
      phase: "enumeration",
      hasFirewall: false,
      hasWAF: false,
    });

    expect(withFirewall).toMatch(/firewall|evasion/i);
    // Without firewall flag, firewall evasion context should not be included
    // (but subdomain/shodan still will be)
  });

  it("phishing knowledge composition includes all sections", () => {
    const ctx = buildPhishingKnowledgeContext({ includeLandingPages: true });
    expect(ctx).toContain("GoPhish");
    expect(ctx).toContain("Pretext");
    expect(ctx).toContain("Landing Page");
  });
});

// ─── Token Budget Tests ─────────────────────────────────────────────────────

describe("Token Budget Constraints", () => {
  it("individual module contexts stay under 5KB", () => {
    const contexts = [
      getLOTLContext("linux"),
      getLOTLContext("windows"),
      getFileUploadBypassContext(),
      getFirewallEvasionContext(true, true),
      getSocialEngineeringContext(),
      getShodanReconContext(),
      getSubdomainEnumContext(),
    ];

    for (const ctx of contexts) {
      expect(ctx.length).toBeLessThan(5000);
    }
  });

  it("GoPhish templates context stays under 8KB", () => {
    const ctx = getGoPhishTemplatesContext();
    expect(ctx.length).toBeLessThan(8000);
  });

  it("full phishing knowledge stays under 15KB", () => {
    const ctx = buildPhishingKnowledgeContext({ includeLandingPages: true });
    expect(ctx.length).toBeLessThan(15000);
  });

  it("worst-case phase context stays under 15KB", () => {
    // Exploitation with everything enabled is the heaviest
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includePhishing: true,
      platform: "windows",
    });
    expect(ctx.length).toBeLessThan(15000);
  });
});

// ─── Social Engineering Templates Data Quality ──────────────────────────────

describe("Social Engineering Templates Data Quality", () => {
  it("all GoPhish templates have unique IDs", () => {
    const ids = GOPHISH_TEMPLATES.map(t => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all pretext scripts have unique IDs", () => {
    const ids = PRETEXT_SCRIPTS.map(s => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all landing page patterns have unique types", () => {
    const types = LANDING_PAGE_PATTERNS.map(lp => lp.type);
    expect(new Set(types).size).toBe(types.length);
  });

  it("metadata counts match actual data", () => {
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.templateCount).toBe(GOPHISH_TEMPLATES.length);
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.pretextScriptCount).toBe(PRETEXT_SCRIPTS.length);
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.landingPagePatternCount).toBe(LANDING_PAGE_PATTERNS.length);
  });

  it("all templates have valid MITRE technique IDs", () => {
    for (const t of GOPHISH_TEMPLATES) {
      expect(t.mitreTechnique).toMatch(/^T\d{4}/);
    }
    for (const s of PRETEXT_SCRIPTS) {
      expect(s.mitreTechnique).toMatch(/^T\d{4}/);
    }
  });

  it("all GoPhish templates contain required placeholders", () => {
    for (const t of GOPHISH_TEMPLATES) {
      expect(t.htmlBody).toContain("{{.URL}}");
      expect(t.textBody).toContain("{{.URL}}");
    }
  });

  it("category filtering returns correct subsets", () => {
    const becTemplates = getGoPhishTemplatesContext("bec");
    expect(becTemplates).toContain("Wire Transfer");
    expect(becTemplates).not.toContain("Microsoft 365");

    const phishScripts = getPretextScriptsContext("phishing");
    expect(phishScripts).toContain("Credential Harvest");
    expect(phishScripts).not.toContain("USB Drop");
  });
});
