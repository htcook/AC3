/**
 * Social Engineering Templates Module
 *
 * Data is loaded at runtime from the DO scan server's /api/knowledge/ endpoint.
 */

import { loadKnowledgeData } from "./knowledge-loader";

export interface GoPhishTemplate {
  id: string;
  name: string;
  category: "bec" | "credential_harvest" | "it_support" | "invoice_lure" | "compliance" | "shared_doc" | "mfa_reset" | "delivery_notification";
  mitreTechnique: string;
  targetRole: string[];
  subject: string;
  htmlBody: string;
  textBody: string;
  indicators: string[];
  landingPageType: "login_clone" | "document_viewer" | "mfa_prompt" | "form_submission";
  successMetrics: string[];
}

export interface PretextScript {
  id: string;
  category: "phishing" | "pretexting" | "baiting" | "quid_pro_quo" | "tailgating";
  subTechnique: string;
  mitreTechnique: string;
  scenario: string;
  openingLine: string;
  keyTalkingPoints: string[];
  escalationTriggers: string[];
  exitStrategy: string;
  targetProfile: string;
  channelType: "email" | "phone" | "sms" | "in_person" | "social_media";
}

export interface LandingPagePattern {
  type: "login_clone" | "document_viewer" | "mfa_prompt" | "form_submission";
  description: string;
  captureFields: string[];
  bestPractices: string[];
}

// ─── Data Loading ──────────────────────────────────────────────────────────

interface SocialEngData {
  gophishTemplates: GoPhishTemplate[];
  pretextScripts: PretextScript[];
  landingPagePatterns: LandingPagePattern[];
}

const FALLBACK: SocialEngData = { gophishTemplates: [], pretextScripts: [], landingPagePatterns: [] };

let GOPHISH_TEMPLATES: GoPhishTemplate[] = [];
let PRETEXT_SCRIPTS: PretextScript[] = [];
let LANDING_PAGE_PATTERNS: LandingPagePattern[] = [];
let _loaded = false;

export async function initSocialEngTemplates(): Promise<void> {
  if (_loaded) return;
  const data = await loadKnowledgeData<SocialEngData>("social_engineering_templates.json", FALLBACK);
  GOPHISH_TEMPLATES = data.gophishTemplates || [];
  PRETEXT_SCRIPTS = data.pretextScripts || [];
  LANDING_PAGE_PATTERNS = data.landingPagePatterns || [];
  _loaded = true;
  console.log(`[SocialEng] Loaded ${GOPHISH_TEMPLATES.length} templates, ${PRETEXT_SCRIPTS.length} scripts, ${LANDING_PAGE_PATTERNS.length} patterns`);
}

initSocialEngTemplates().catch(e => console.warn("[SocialEng] Auto-init failed:", e.message));

export { GOPHISH_TEMPLATES, PRETEXT_SCRIPTS, LANDING_PAGE_PATTERNS };

export function getGoPhishTemplatesContext(category?: GoPhishTemplate["category"]): string {
  const templates = category
    ? GOPHISH_TEMPLATES.filter(t => t.category === category)
    : GOPHISH_TEMPLATES;

  const formatted = templates.map(t => `### ${t.name} [${t.category.toUpperCase()}]
**MITRE:** ${t.mitreTechnique} | **Target Roles:** ${t.targetRole.join(", ")}
**Subject:** ${t.subject}
**Indicators:** ${t.indicators.join(", ")}
**Landing Page:** ${t.landingPageType}
**Success Metrics:** ${t.successMetrics.join(", ")}
`).join("\n");

  return `## GoPhish Email Template Examples
Reference these proven templates when generating phishing campaign content:

${formatted}
**Template Selection Guide:**
- **Executives/Finance:** BEC wire transfer, invoice lure
- **All Staff:** Credential harvest (O365/Google), shared doc, compliance training
- **IT Staff:** Security update, MFA reset
- **Remote Workers:** VPN update, delivery notification`;
}

export function getPretextScriptsContext(category?: PretextScript["category"]): string {
  const scripts = category
    ? PRETEXT_SCRIPTS.filter(s => s.category === category)
    : PRETEXT_SCRIPTS;

  const formatted = scripts.map(s => `### ${s.subTechnique} — ${s.scenario.slice(0, 80)}...
**Category:** ${s.category} | **MITRE:** ${s.mitreTechnique} | **Channel:** ${s.channelType}
**Opening:** "${s.openingLine.slice(0, 120)}..."
**Key Points:**
${s.keyTalkingPoints.map(p => `  - ${p}`).join("\n")}
**Target Profile:** ${s.targetProfile}
**Exit Strategy:** ${s.exitStrategy}
`).join("\n");

  return `## Pretext Scripts & Social Engineering Playbooks
Use these scripts as templates when planning social engineering engagements:

${formatted}
**Execution Tips:**
- Always research the target organization's culture, tools, and vendors before engaging
- Layer multiple channels: email pretext → phone follow-up → physical access
- Document all interactions for the engagement report
- Have an exit strategy ready before every interaction`;
}

export function getLandingPagePatternsContext(): string {
  const formatted = LANDING_PAGE_PATTERNS.map(lp => `### ${lp.type.replace(/_/g, " ").toUpperCase()}
${lp.description}
**Capture Fields:** ${lp.captureFields.join(", ")}
**Best Practices:**
${lp.bestPractices.map(bp => `  - ${bp}`).join("\n")}
`).join("\n");

  return `## Landing Page Patterns for Credential Harvesting
${formatted}`;
}

export function buildPhishingKnowledgeContext(params?: {
  templateCategory?: GoPhishTemplate["category"];
  pretextCategory?: PretextScript["category"];
  includeLandingPages?: boolean;
}): string {
  const sections: string[] = [];

  sections.push(getGoPhishTemplatesContext(params?.templateCategory));
  sections.push(getPretextScriptsContext(params?.pretextCategory));

  if (params?.includeLandingPages !== false) {
    sections.push(getLandingPagePatternsContext());
  }

  return sections.join("\n\n---\n\n");
}

export const SOCIAL_ENGINEERING_TEMPLATES_METADATA = new Proxy({} as Record<string, any>, {
  get(_, prop) {
    const meta: Record<string, any> = {
      totalTemplates: GOPHISH_TEMPLATES.length,
      totalPretexts: PRETEXT_SCRIPTS.length,
      totalLandingPages: LANDING_PAGE_PATTERNS.length,
      templateCount: GOPHISH_TEMPLATES.length,
      pretextScriptCount: PRETEXT_SCRIPTS.length,
      landingPagePatternCount: LANDING_PAGE_PATTERNS.length,
      categories: Array.from(new Set(GOPHISH_TEMPLATES.map(t => t.category))),
      mitreTechniques: Array.from(new Set([
        ...GOPHISH_TEMPLATES.map(t => t.mitreTechnique),
        ...PRETEXT_SCRIPTS.map(s => s.mitreTechnique),
      ])),
    };
    return meta[prop as string];
  },
});
