/**
 * Phase 6b: Social Engineering Assessment
 *
 * Extracted from engagement-orchestrator.ts to reduce complexity.
 * Handles ROE-gated social engineering / phishing intelligence gathering.
 *
 * This phase:
 * 1. Checks if social engineering is authorized in the ROE scope
 * 2. Assesses domain spoofability from passive recon (SPF/DKIM/DMARC)
 * 3. Uses LLM to generate phishing campaign recommendations
 * 4. Stores phishing intelligence for the final report
 */

import { throttledLLMCall } from "./llm-throttle";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SocialEngState {
  engagementId: string;
  isRunning: boolean;
  phase: string;
  currentAction: string;
  assets: Array<{
    hostname: string;
    ip?: string;
    passiveRecon?: {
      emailSecurity?: {
        spf?: boolean;
        dkim?: boolean;
        dmarc?: boolean;
        dmarcPolicy?: string;
      };
      technologies?: string[];
      services?: Array<{ port: number; service: string }>;
    };
  }>;
  stats: { vulnsFound: number };
}

export interface SocialEngEngagement {
  targetDomain?: string;
  roeScope?: unknown;
}

export interface PhishingIntel {
  authorized: boolean;
  spoofable: boolean;
  emailSecurity: {
    spf?: boolean;
    dkim?: boolean;
    dmarc?: boolean;
    dmarcPolicy?: string;
  } | undefined;
  recommendation: PhishingRecommendation;
  targetDomain: string;
  assessedAt: number;
}

export interface PhishingRecommendation {
  templateCategory?: string;
  pretext?: string;
  domainStrategy?: "spoof_target" | "typosquat" | "owned_domain";
  landingPageType?: string;
  deliveryNotes?: string;
  confidence?: number;
}

export interface SocialEngResult {
  executed: boolean;
  skipped: boolean;
  skipReason?: string;
  phishingIntel?: PhishingIntel;
  error?: string;
}

// ─── Callbacks (injected by orchestrator to avoid circular deps) ──────────────

export interface SocialEngCallbacks {
  addLog: (entry: { phase: string; type: string; title: string; detail: string; data?: any }) => void;
  broadcastUpdate: (update: { type: string; phase?: string }) => void;
}

// ─── Main Phase Execution ─────────────────────────────────────────────────────

/**
 * Execute Phase 6b: Social Engineering Assessment
 *
 * Returns the phishing intelligence gathered, or a skip/error result.
 * The caller is responsible for state.phase transitions and phaseCheckpoint.
 */
export async function executeSocialEngineering(
  state: SocialEngState,
  engagement: SocialEngEngagement,
  callbacks: SocialEngCallbacks
): Promise<SocialEngResult> {
  const roeScope = engagement.roeScope as any;
  const socialEngAuthorized = roeScope && typeof roeScope === 'object' && (
    roeScope.socialEngineeringAllowed === true ||
    roeScope.socialEngineering === true ||
    roeScope.phishing === true
  );

  if (!socialEngAuthorized) {
    callbacks.addLog({
      phase: 'social_engineering', type: 'info',
      title: '⏭️ Social Engineering Skipped',
      detail: 'Social engineering is not authorized in the Rules of Engagement for this engagement. Skipping to exploitation phase.',
    });
    return { executed: false, skipped: true, skipReason: 'not_authorized_in_roe' };
  }

  // Phase transition
  state.phase = 'social_engineering';
  state.currentAction = 'Preparing social engineering assessment...';
  callbacks.broadcastUpdate({ type: 'phase_change', phase: 'social_engineering' });
  callbacks.addLog({
    phase: 'social_engineering', type: 'info',
    title: '🎣 Phase 6b: Social Engineering Assessment',
    detail: 'Social engineering is authorized in the Rules of Engagement. Analyzing domain spoofability and preparing phishing intelligence.',
  });

  try {
    // Check domain spoofability from recon data
    const targetDomain = engagement.targetDomain || '';
    const primaryAsset = state.assets.find(
      a => a.hostname === targetDomain || a.hostname.endsWith('.' + targetDomain)
    );
    const emailSecurity = primaryAsset?.passiveRecon?.emailSecurity;
    const spoofable = emailSecurity
      ? (!emailSecurity.spf || !emailSecurity.dmarc || emailSecurity.dmarcPolicy === 'none')
      : true;

    // Log domain spoofing assessment
    if (spoofable) {
      callbacks.addLog({
        phase: 'social_engineering', type: 'info',
        title: '✅ Domain Spoofing Viable',
        detail: `Target domain ${targetDomain} has weak email security: SPF=${emailSecurity?.spf ? 'present' : 'MISSING'}, DMARC=${emailSecurity?.dmarc ? 'present' : 'MISSING'}${emailSecurity?.dmarcPolicy ? ` (policy: ${emailSecurity.dmarcPolicy})` : ''}. Direct domain spoofing is recommended.`,
      });
    } else {
      callbacks.addLog({
        phase: 'social_engineering', type: 'info',
        title: '🛡️ Domain Hardened Against Spoofing',
        detail: `Target domain ${targetDomain} has strong email security: SPF=${emailSecurity?.spf ? '✓' : '✗'}, DKIM=${emailSecurity?.dkim ? '✓' : '✗'}, DMARC=${emailSecurity?.dmarc ? '✓' : '✗'} (policy: ${emailSecurity?.dmarcPolicy || 'unknown'}). Use a typosquat or owned domain for phishing.`,
      });
    }

    // Use LLM to generate phishing campaign recommendations based on recon
    const techStack = primaryAsset?.passiveRecon?.technologies || [];
    const services = primaryAsset?.passiveRecon?.services || [];
    const phishingRecommendation = await throttledLLMCall({
      messages: [
        {
          role: 'system',
          content: `You are a social engineering specialist on a red team. Based on the target's technology stack, services, and email security posture, recommend the most effective phishing approach. Be specific about:
1. Email template category (IT Help Desk, Password Reset, Cloud Services, etc.)
2. Pretext scenario tailored to the target's tech stack
3. Whether to spoof the target domain or use an alternate
4. Landing page strategy (credential harvest, malware delivery, or MFA bypass)
5. Timing and delivery recommendations

Respond in JSON: { "templateCategory": string, "pretext": string, "domainStrategy": "spoof_target" | "typosquat" | "owned_domain", "landingPageType": string, "deliveryNotes": string, "confidence": number }`
        },
        {
          role: 'user',
          content: `Target: ${targetDomain}\nTech Stack: ${techStack.join(', ') || 'unknown'}\nServices: ${services.map((s: any) => `${s.port}/${s.service}`).join(', ') || 'unknown'}\nEmail Security: SPF=${emailSecurity?.spf}, DKIM=${emailSecurity?.dkim}, DMARC=${emailSecurity?.dmarc} (policy: ${emailSecurity?.dmarcPolicy || 'unknown'})\nSpoofable: ${spoofable}\nVulns found so far: ${state.stats.vulnsFound}`,
        },
      ],
      response_format: { type: 'json_object' as const },
    });

    const rawContent = phishingRecommendation.choices[0]?.message?.content;
    const contentStr = typeof rawContent === 'string' ? rawContent : JSON.stringify(rawContent) || '{}';
    const phishRec: PhishingRecommendation = JSON.parse(contentStr);

    callbacks.addLog({
      phase: 'social_engineering', type: 'info',
      title: '📋 Phishing Campaign Recommendation',
      detail: `Category: ${phishRec.templateCategory || 'General'}\nPretext: ${phishRec.pretext || 'N/A'}\nDomain Strategy: ${phishRec.domainStrategy || 'unknown'}\nLanding Page: ${phishRec.landingPageType || 'credential harvest'}\nDelivery: ${phishRec.deliveryNotes || 'N/A'}\nConfidence: ${phishRec.confidence || 'N/A'}%`,
      data: { phishingRecommendation: phishRec, spoofable, emailSecurity },
    });

    const phishingIntel: PhishingIntel = {
      authorized: true,
      spoofable,
      emailSecurity,
      recommendation: phishRec,
      targetDomain,
      assessedAt: Date.now(),
    };

    callbacks.addLog({
      phase: 'social_engineering', type: 'phase_complete',
      title: '✅ Phase 6b Complete',
      detail: `Social engineering assessment complete. ${spoofable ? 'Domain spoofing viable.' : 'Domain hardened — alternate domain required.'} Campaign recommendation generated. Operator can launch phishing campaign from the Phishing Operations module.`,
    });

    return { executed: true, skipped: false, phishingIntel };
  } catch (phishErr: any) {
    callbacks.addLog({
      phase: 'social_engineering', type: 'warning',
      title: 'Social Engineering Assessment Error',
      detail: `Failed to complete phishing assessment: ${phishErr.message}. Continuing to exploitation phase.`,
    });
    return { executed: false, skipped: false, error: phishErr.message };
  }
}
