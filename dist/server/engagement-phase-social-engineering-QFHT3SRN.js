import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-2HOIKPO3.js";
import "./chunk-UAG3IV7V.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-phase-social-engineering.ts
async function executeSocialEngineering(state, engagement, callbacks) {
  const roeScope = engagement.roeScope;
  const socialEngAuthorized = roeScope && typeof roeScope === "object" && (roeScope.socialEngineeringAllowed === true || roeScope.socialEngineering === true || roeScope.phishing === true);
  if (!socialEngAuthorized) {
    callbacks.addLog({
      phase: "social_engineering",
      type: "info",
      title: "\u23ED\uFE0F Social Engineering Skipped",
      detail: "Social engineering is not authorized in the Rules of Engagement for this engagement. Skipping to exploitation phase."
    });
    return { executed: false, skipped: true, skipReason: "not_authorized_in_roe" };
  }
  state.phase = "social_engineering";
  state.currentAction = "Preparing social engineering assessment...";
  callbacks.broadcastUpdate({ type: "phase_change", phase: "social_engineering" });
  callbacks.addLog({
    phase: "social_engineering",
    type: "info",
    title: "\u{1F3A3} Phase 6b: Social Engineering Assessment",
    detail: "Social engineering is authorized in the Rules of Engagement. Analyzing domain spoofability and preparing phishing intelligence."
  });
  try {
    const targetDomain = engagement.targetDomain || "";
    const primaryAsset = state.assets.find(
      (a) => a.hostname === targetDomain || a.hostname.endsWith("." + targetDomain)
    );
    const emailSecurity = primaryAsset?.passiveRecon?.emailSecurity;
    const spoofable = emailSecurity ? !emailSecurity.spf || !emailSecurity.dmarc || emailSecurity.dmarcPolicy === "none" : true;
    if (spoofable) {
      callbacks.addLog({
        phase: "social_engineering",
        type: "info",
        title: "\u2705 Domain Spoofing Viable",
        detail: `Target domain ${targetDomain} has weak email security: SPF=${emailSecurity?.spf ? "present" : "MISSING"}, DMARC=${emailSecurity?.dmarc ? "present" : "MISSING"}${emailSecurity?.dmarcPolicy ? ` (policy: ${emailSecurity.dmarcPolicy})` : ""}. Direct domain spoofing is recommended.`
      });
    } else {
      callbacks.addLog({
        phase: "social_engineering",
        type: "info",
        title: "\u{1F6E1}\uFE0F Domain Hardened Against Spoofing",
        detail: `Target domain ${targetDomain} has strong email security: SPF=${emailSecurity?.spf ? "\u2713" : "\u2717"}, DKIM=${emailSecurity?.dkim ? "\u2713" : "\u2717"}, DMARC=${emailSecurity?.dmarc ? "\u2713" : "\u2717"} (policy: ${emailSecurity?.dmarcPolicy || "unknown"}). Use a typosquat or owned domain for phishing.`
      });
    }
    const techStack = primaryAsset?.passiveRecon?.technologies || [];
    const services = primaryAsset?.passiveRecon?.services || [];
    const phishingRecommendation = await throttledLLMCall({
      messages: [
        {
          role: "system",
          content: `You are a social engineering specialist on a red team. Based on the target's technology stack, services, and email security posture, recommend the most effective phishing approach. Be specific about:
1. Email template category (IT Help Desk, Password Reset, Cloud Services, etc.)
2. Pretext scenario tailored to the target's tech stack
3. Whether to spoof the target domain or use an alternate
4. Landing page strategy (credential harvest, malware delivery, or MFA bypass)
5. Timing and delivery recommendations

Respond in JSON: { "templateCategory": string, "pretext": string, "domainStrategy": "spoof_target" | "typosquat" | "owned_domain", "landingPageType": string, "deliveryNotes": string, "confidence": number }`
        },
        {
          role: "user",
          content: `Target: ${targetDomain}
Tech Stack: ${techStack.join(", ") || "unknown"}
Services: ${services.map((s) => `${s.port}/${s.service}`).join(", ") || "unknown"}
Email Security: SPF=${emailSecurity?.spf}, DKIM=${emailSecurity?.dkim}, DMARC=${emailSecurity?.dmarc} (policy: ${emailSecurity?.dmarcPolicy || "unknown"})
Spoofable: ${spoofable}
Vulns found so far: ${state.stats.vulnsFound}`
        }
      ],
      response_format: { type: "json_object" }
    });
    const rawContent = phishingRecommendation.choices[0]?.message?.content;
    const contentStr = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent) || "{}";
    const phishRec = JSON.parse(contentStr);
    callbacks.addLog({
      phase: "social_engineering",
      type: "info",
      title: "\u{1F4CB} Phishing Campaign Recommendation",
      detail: `Category: ${phishRec.templateCategory || "General"}
Pretext: ${phishRec.pretext || "N/A"}
Domain Strategy: ${phishRec.domainStrategy || "unknown"}
Landing Page: ${phishRec.landingPageType || "credential harvest"}
Delivery: ${phishRec.deliveryNotes || "N/A"}
Confidence: ${phishRec.confidence || "N/A"}%`,
      data: { phishingRecommendation: phishRec, spoofable, emailSecurity }
    });
    const phishingIntel = {
      authorized: true,
      spoofable,
      emailSecurity,
      recommendation: phishRec,
      targetDomain,
      assessedAt: Date.now()
    };
    callbacks.addLog({
      phase: "social_engineering",
      type: "phase_complete",
      title: "\u2705 Phase 6b Complete",
      detail: `Social engineering assessment complete. ${spoofable ? "Domain spoofing viable." : "Domain hardened \u2014 alternate domain required."} Campaign recommendation generated. Operator can launch phishing campaign from the Phishing Operations module.`
    });
    return { executed: true, skipped: false, phishingIntel };
  } catch (phishErr) {
    callbacks.addLog({
      phase: "social_engineering",
      type: "warning",
      title: "Social Engineering Assessment Error",
      detail: `Failed to complete phishing assessment: ${phishErr.message}. Continuing to exploitation phase.`
    });
    return { executed: false, skipped: false, error: phishErr.message };
  }
}
var init_engagement_phase_social_engineering = __esm({
  "server/lib/engagement-phase-social-engineering.ts"() {
    init_llm_throttle();
  }
});
init_engagement_phase_social_engineering();
export {
  executeSocialEngineering
};
