import {
  generatePostExploitPlaybook,
  init_c2_tactical_knowledge
} from "./chunk-OHFP7XLR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit-auto-trigger.ts
async function triggerPostExploitPlaybook(event, autoTriggered = false) {
  const triggeredAt = (/* @__PURE__ */ new Date()).toISOString();
  try {
    console.log(
      `[PostExploit] ${autoTriggered ? "Auto-" : ""}Triggering playbook for engagement #${event.engagementId} (${event.targetHost}, ${event.targetPlatform}, ${event.shellPrivilege})`
    );
    const playbook = generatePostExploitPlaybook({
      shellPrivilege: event.shellPrivilege,
      targetPlatform: event.targetPlatform,
      objectives: event.objectives || ["Full compromise assessment"],
      availableFrameworks: [
        "caldera",
        "metasploit",
        "sliver",
        "empire",
        "cobaltstrike",
        "manjusaka"
      ],
      hasActiveDirectory: event.hasActiveDirectory ?? false,
      targetDefenses: [],
      threatActorToEmulate: event.threatActorToEmulate
    });
    engagementPlaybooks.set(event.engagementId, {
      playbook,
      triggeredAt,
      shellEvent: event,
      autoTriggered
    });
    triggerHistory.push({
      engagementId: event.engagementId,
      targetHost: event.targetHost,
      targetPlatform: event.targetPlatform,
      shellPrivilege: event.shellPrivilege,
      triggeredAt,
      autoTriggered,
      stepCount: playbook.steps.length,
      success: true
    });
    if (triggerHistory.length > 200) {
      triggerHistory.splice(0, triggerHistory.length - 200);
    }
    console.log(
      `[PostExploit] Generated ${playbook.steps.length}-step playbook for engagement #${event.engagementId}`
    );
    try {
      const { emitPlaybookTriggered } = await import("./ws-event-hub-GYTLNKYI.js");
      emitPlaybookTriggered({
        engagementId: event.engagementId,
        targetHost: event.targetHost,
        targetPlatform: event.targetPlatform,
        privilegeLevel: event.shellPrivilege,
        playbookSteps: playbook.steps.length,
        framework: playbook.recommendedFramework
      });
    } catch (e) {
      console.warn(`[PostExploit] WS event emission failed:`, e.message);
    }
    if (autoTriggered) {
      try {
        const { notifyOwner } = await import("./notification-4RFY3TAD.js");
        await notifyOwner({
          title: `Post-Exploit Playbook Generated \u2014 Engagement #${event.engagementId}`,
          content: `A ${playbook.steps.length}-step post-exploitation playbook was auto-generated for ${event.targetHost} (${event.targetPlatform}, ${event.shellPrivilege} shell).

Phases: ${playbook.steps.map((s) => s.phase).filter((v, i, a) => a.indexOf(v) === i).join(" \u2192 ")}

Review the playbook in the C2 Knowledge Base.`
        });
      } catch (e) {
        console.warn(`[PostExploit] Notification failed:`, e.message);
      }
    }
    return {
      success: true,
      engagementId: event.engagementId,
      playbook,
      triggeredAt,
      autoTriggered
    };
  } catch (err) {
    console.error(`[PostExploit] Failed to generate playbook:`, err.message);
    triggerHistory.push({
      engagementId: event.engagementId,
      targetHost: event.targetHost,
      targetPlatform: event.targetPlatform,
      shellPrivilege: event.shellPrivilege,
      triggeredAt,
      autoTriggered,
      stepCount: 0,
      success: false,
      error: err.message
    });
    return {
      success: false,
      engagementId: event.engagementId,
      playbook: null,
      triggeredAt,
      autoTriggered,
      error: err.message
    };
  }
}
function getPostExploitPlaybookForEngagement(engagementId) {
  return engagementPlaybooks.get(engagementId) || null;
}
function getPostExploitTriggerHistory() {
  return [...triggerHistory].reverse();
}
async function onShellObtained(params) {
  const platform = detectPlatform(params.exploitOutput || "");
  const privilege = detectPrivilege(params.exploitOutput || "", params.shellType);
  if (!platform) {
    console.log(
      `[PostExploit] Could not detect platform for ${params.targetHost}, skipping auto-trigger`
    );
    return null;
  }
  return triggerPostExploitPlaybook(
    {
      engagementId: params.engagementId,
      targetHost: params.targetHost,
      targetPort: params.targetPort,
      shellPrivilege: privilege,
      targetPlatform: platform,
      shellSessionId: params.shellSessionId,
      shellType: params.shellType
    },
    true
    // autoTriggered
  );
}
function detectPlatform(output) {
  const lower = output.toLowerCase();
  if (/windows|win32|win64|nt authority|c:\\|powershell|cmd\.exe|microsoft/i.test(lower)) {
    return "windows";
  }
  if (/darwin|macos|mac os x|apple|\/usr\/sbin\/softwareupdate/i.test(lower)) {
    return "macos";
  }
  if (/linux|ubuntu|debian|centos|fedora|rhel|kali|\/etc\/passwd|\/bin\/bash|\/bin\/sh|www-data/i.test(
    lower
  )) {
    return "linux";
  }
  if (/\$\s*$|#\s*$/m.test(output)) return "linux";
  if (/>\s*$/m.test(output)) return "windows";
  return null;
}
function detectPrivilege(output, shellType) {
  const lower = output.toLowerCase();
  if (/root@|uid=0|nt authority\\system|system32/i.test(lower)) return "root";
  if (shellType === "meterpreter" && /getsystem|nt authority/i.test(lower)) return "system";
  if (/administrator|admin@|sudo.*password|wheel/i.test(lower)) return "admin";
  return "user";
}
function registerPostExploitListener() {
  console.log("[PostExploit] Auto-trigger listener registered");
}
var engagementPlaybooks, triggerHistory;
var init_post_exploit_auto_trigger = __esm({
  "server/lib/post-exploit-auto-trigger.ts"() {
    init_c2_tactical_knowledge();
    engagementPlaybooks = /* @__PURE__ */ new Map();
    triggerHistory = [];
  }
});

export {
  triggerPostExploitPlaybook,
  getPostExploitPlaybookForEngagement,
  getPostExploitTriggerHistory,
  onShellObtained,
  registerPostExploitListener,
  init_post_exploit_auto_trigger
};
