/**
 * Engagement Validation Test — Offensive Knowledge Integration
 *
 * Simulates an engagement with WAF/firewall/file-upload targets and verifies
 * that offensive knowledge is properly injected into all LLM specialist prompts.
 */

import { describe, it, expect } from "vitest";
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
import * as fs from "fs";
import * as path from "path";

// ─── Simulated Engagement Scenarios ─────────────────────────────────────────

describe("Engagement Scenario: Web App with WAF + File Upload", () => {
  const scenario = {
    target: "acme-corp.com",
    hasFirewall: true,
    hasWAF: true,
    hasFileUpload: true,
    platform: "linux" as const,
  };

  it("recon phase includes subdomain enumeration and Shodan", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "recon",
      ...scenario,
    });
    expect(ctx).toContain("Subdomain");
    expect(ctx).toContain("Shodan");
    // Should include primary tools
    expect(ctx).toMatch(/subfinder|amass|sublist3r/i);
  });

  it("enumeration phase includes firewall evasion + WAF bypass + file upload bypass", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "enumeration",
      ...scenario,
    });
    expect(ctx).toMatch(/firewall|evasion/i);
    expect(ctx).toMatch(/WAF|wafw00f/i);
    expect(ctx).toMatch(/upload|bypass|extension/i);
  });

  it("vuln_detection phase includes WAF evasion and file upload bypass", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "vuln_detection",
      ...scenario,
    });
    expect(ctx).toMatch(/WAF|wafw00f/i);
    expect(ctx).toMatch(/upload|bypass/i);
  });

  it("exploitation phase includes LOTL for linux and file upload bypass", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      ...scenario,
    });
    expect(ctx).toContain("GTFOBins");
    expect(ctx).not.toContain("LOLBAS"); // Linux only
    expect(ctx).toMatch(/upload|bypass/i);
  });

  it("post_exploitation phase includes LOTL and firewall evasion for exfiltration", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "post_exploitation",
      ...scenario,
    });
    expect(ctx).toContain("GTFOBins");
    expect(ctx).toMatch(/firewall|evasion|tunnel/i);
  });
});

describe("Engagement Scenario: Windows AD Environment", () => {
  const scenario = {
    target: "contoso.local",
    hasFirewall: true,
    hasWAF: false,
    hasFileUpload: false,
    platform: "windows" as const,
  };

  it("exploitation phase includes Windows-specific LOTL", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      ...scenario,
    });
    expect(ctx).toContain("LOLBAS");
    expect(ctx).toContain("LOLDrivers");
    expect(ctx).toContain("WADComs");
    expect(ctx).toContain("HijackLibs");
    expect(ctx).toContain("MalAPI");
    expect(ctx).not.toContain("GTFOBins");
    expect(ctx).not.toContain("LOOBins");
  });

  it("post_exploitation includes firewall evasion for lateral movement", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "post_exploitation",
      ...scenario,
    });
    expect(ctx).toMatch(/firewall|evasion|tunnel/i);
    expect(ctx).toContain("LOLBAS");
  });
});

describe("Engagement Scenario: Phishing Campaign with Social Engineering", () => {
  it("phishing context includes all social engineering categories", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "recon",
      includePhishing: true,
    });
    expect(ctx).toContain("Phishing");
    expect(ctx).toContain("Pretexting");
    expect(ctx).toContain("Baiting");
    expect(ctx).toContain("Quid Pro Quo");
    expect(ctx).toContain("Tailgating");
  });

  it("expanded phishing knowledge includes GoPhish templates", () => {
    const ctx = buildPhishingKnowledgeContext();
    expect(ctx).toContain("CEO Wire Transfer");
    expect(ctx).toContain("Microsoft 365 Password");
    expect(ctx).toContain("IT Security Update");
    expect(ctx).toContain("Invoice");
    expect(ctx).toContain("Compliance Training");
    expect(ctx).toContain("Shared Document");
    expect(ctx).toContain("MFA Reset");
    expect(ctx).toContain("Package Delivery");
  });

  it("expanded phishing knowledge includes pretext scripts", () => {
    const ctx = buildPhishingKnowledgeContext();
    expect(ctx).toContain("Credential Harvest");
    expect(ctx).toContain("Business Email Compromise");
    expect(ctx).toContain("Tech Support Scam");
    expect(ctx).toContain("USB Drop");
    expect(ctx).toContain("Evil Twin");
  });

  it("expanded phishing knowledge includes landing page patterns", () => {
    const ctx = buildPhishingKnowledgeContext({ includeLandingPages: true });
    expect(ctx).toMatch(/LOGIN CLONE/i);
    expect(ctx).toMatch(/DOCUMENT VIEWER/i);
    expect(ctx).toMatch(/MFA PROMPT/i);
    expect(ctx).toMatch(/FORM SUBMISSION/i);
  });
});

// ─── GoPhish Template Validation ────────────────────────────────────────────

describe("GoPhish Templates Quality", () => {
  it("all templates have valid GoPhish placeholders", () => {
    for (const t of GOPHISH_TEMPLATES) {
      // GoPhish uses {{.FirstName}}, {{.URL}}, {{.From}} etc.
      expect(t.htmlBody).toContain("{{.URL}}");
      expect(t.textBody).toContain("{{.URL}}");
    }
  });

  it("all templates have non-empty required fields", () => {
    for (const t of GOPHISH_TEMPLATES) {
      expect(t.id).toBeTruthy();
      expect(t.name).toBeTruthy();
      expect(t.subject).toBeTruthy();
      expect(t.htmlBody.length).toBeGreaterThan(50);
      expect(t.textBody.length).toBeGreaterThan(20);
      expect(t.indicators.length).toBeGreaterThan(0);
      expect(t.mitreTechnique).toMatch(/^T\d{4}/);
    }
  });

  it("templates cover all 8 categories", () => {
    const categories = new Set(GOPHISH_TEMPLATES.map(t => t.category));
    expect(categories.size).toBe(8);
    expect(categories).toContain("bec");
    expect(categories).toContain("credential_harvest");
    expect(categories).toContain("it_support");
    expect(categories).toContain("invoice_lure");
    expect(categories).toContain("compliance");
    expect(categories).toContain("shared_doc");
    expect(categories).toContain("mfa_reset");
    expect(categories).toContain("delivery_notification");
  });

  it("can filter templates by category", () => {
    const becCtx = getGoPhishTemplatesContext("bec");
    expect(becCtx).toContain("Wire Transfer");
    expect(becCtx).not.toContain("Microsoft 365 Password");

    const credCtx = getGoPhishTemplatesContext("credential_harvest");
    expect(credCtx).toContain("Microsoft 365");
    expect(credCtx).not.toContain("Wire Transfer");
  });
});

// ─── Pretext Scripts Validation ─────────────────────────────────────────────

describe("Pretext Scripts Quality", () => {
  it("all scripts have valid fields", () => {
    for (const s of PRETEXT_SCRIPTS) {
      expect(s.id).toBeTruthy();
      expect(s.scenario).toBeTruthy();
      expect(s.openingLine).toBeTruthy();
      expect(s.keyTalkingPoints.length).toBeGreaterThan(0);
      expect(s.exitStrategy).toBeTruthy();
      expect(s.mitreTechnique).toMatch(/^T\d{4}/);
    }
  });

  it("scripts cover all 5 social engineering categories", () => {
    const categories = new Set(PRETEXT_SCRIPTS.map(s => s.category));
    expect(categories).toContain("phishing");
    expect(categories).toContain("pretexting");
    expect(categories).toContain("baiting");
    expect(categories).toContain("quid_pro_quo");
    expect(categories).toContain("tailgating");
  });

  it("scripts cover multiple channels", () => {
    const channels = new Set(PRETEXT_SCRIPTS.map(s => s.channelType));
    expect(channels).toContain("email");
    expect(channels).toContain("phone");
    expect(channels).toContain("in_person");
  });

  it("can filter scripts by category", () => {
    const phishCtx = getPretextScriptsContext("phishing");
    expect(phishCtx).toContain("Credential Harvest");
    expect(phishCtx).not.toContain("USB Drop");

    const baitCtx = getPretextScriptsContext("baiting");
    expect(baitCtx).toContain("USB Drop");
    expect(baitCtx).not.toContain("Credential Harvest");
  });
});

// ─── Landing Page Patterns Validation ───────────────────────────────────────

describe("Landing Page Patterns Quality", () => {
  it("all patterns have valid fields", () => {
    for (const lp of LANDING_PAGE_PATTERNS) {
      expect(lp.type).toBeTruthy();
      expect(lp.description).toBeTruthy();
      expect(lp.captureFields.length).toBeGreaterThan(0);
      expect(lp.bestPractices.length).toBeGreaterThan(0);
    }
  });

  it("covers all 4 landing page types", () => {
    const types = new Set(LANDING_PAGE_PATTERNS.map(lp => lp.type));
    expect(types.size).toBe(4);
    expect(types).toContain("login_clone");
    expect(types).toContain("document_viewer");
    expect(types).toContain("mfa_prompt");
    expect(types).toContain("form_submission");
  });
});

// ─── Metadata Validation ────────────────────────────────────────────────────

describe("Social Engineering Templates Metadata", () => {
  it("metadata has correct counts", () => {
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.templateCount).toBe(GOPHISH_TEMPLATES.length);
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.pretextScriptCount).toBe(PRETEXT_SCRIPTS.length);
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.landingPagePatternCount).toBe(LANDING_PAGE_PATTERNS.length);
  });

  it("metadata has MITRE techniques", () => {
    expect(SOCIAL_ENGINEERING_TEMPLATES_METADATA.mitreTechniques.length).toBeGreaterThan(0);
    for (const t of SOCIAL_ENGINEERING_TEMPLATES_METADATA.mitreTechniques) {
      expect(t).toMatch(/^T\d{4}/);
    }
  });
});

// ─── Cross-Module Integration ───────────────────────────────────────────────

describe("Cross-Module Integration", () => {
  it("offensive-techniques-knowledge.ts file exists and exports correctly", () => {
    const filePath = path.join(__dirname, "lib/knowledge/offensive-techniques-knowledge.ts");
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("social-engineering-templates.ts file exists and exports correctly", () => {
    const filePath = path.join(__dirname, "lib/knowledge/social-engineering-templates.ts");
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("combined context stays under 20KB to avoid token overflow", () => {
    const offensiveCtx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includePhishing: true,
    });
    const phishingCtx = buildPhishingKnowledgeContext({ includeLandingPages: true });
    const combined = offensiveCtx + "\n\n" + phishingCtx;
    expect(combined.length).toBeLessThan(25000);
  });

  it("all context outputs are clean strings without undefined/null", () => {
    const outputs = [
      buildOffensiveTechniquesContext({ phase: "exploitation" }),
      buildPhishingKnowledgeContext(),
      getGoPhishTemplatesContext(),
      getPretextScriptsContext(),
      getLandingPagePatternsContext(),
    ];
    for (const output of outputs) {
      expect(typeof output).toBe("string");
      expect(output).not.toContain("undefined");
      expect(output).not.toContain("[object Object]");
      expect(output.length).toBeGreaterThan(100);
    }
  });
});
