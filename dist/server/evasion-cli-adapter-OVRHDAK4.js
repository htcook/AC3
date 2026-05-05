import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/evasion-cli-adapter.ts
function getEffectiveEvasionProfile(targetProfile) {
  const escalation = targetProfile.evasionEscalation;
  if (escalation && escalation.currentLevel > 1) {
    const strategy = targetProfile.recommendedStrategy;
    const baseProfile = strategy?.evasionProfile;
    return baseProfile || null;
  }
  return targetProfile.recommendedStrategy?.evasionProfile || null;
}
function buildToolEvasionFlags(evasionProfile, escalation) {
  const level = escalation?.currentLevel || 1;
  const rateLimit = evasionProfile.rateLimit || 150;
  const delayMs = evasionProfile.delayMs || 0;
  const userAgent = evasionProfile.userAgentStrategy === "browser_mimic" ? BROWSER_USER_AGENTS[Math.floor(Math.random() * BROWSER_USER_AGENTS.length)] : void 0;
  const headerFlags = [];
  if (evasionProfile.headerManipulation) {
    for (const [key, value] of Object.entries(evasionProfile.headerManipulation)) {
      headerFlags.push(`-H "${key}: ${value}"`);
    }
  }
  if (userAgent) {
    headerFlags.push(`-H "User-Agent: ${userAgent}"`);
  }
  const nucleiFlags = [];
  nucleiFlags.push(`-rate-limit ${rateLimit}`);
  if (level >= 2) nucleiFlags.push(`-bulk-size 10`);
  if (level >= 3) nucleiFlags.push(`-concurrency 5`);
  if (level >= 4) nucleiFlags.push(`-timeout 15`);
  if (level >= 5) nucleiFlags.push(`-timeout 30`);
  for (const hf of headerFlags) nucleiFlags.push(hf);
  const httpxFlags = [];
  httpxFlags.push(`-rate-limit ${Math.min(rateLimit, 50)}`);
  if (level >= 2) httpxFlags.push(`-timeout 10`);
  if (level >= 3) httpxFlags.push(`-retries 2`);
  if (level >= 4) httpxFlags.push(`-timeout 20`);
  for (const hf of headerFlags) httpxFlags.push(hf);
  const naabuFlags = [];
  naabuFlags.push(`-rate ${Math.min(rateLimit * 10, 1e3)}`);
  if (level >= 3) naabuFlags.push(`-retries 2`);
  if (level >= 4) naabuFlags.push(`-rate ${Math.min(rateLimit * 5, 200)}`);
  const gobusterFlags = [];
  if (level >= 2) gobusterFlags.push(`-t ${Math.max(5, Math.floor(20 / level))}`);
  if (level >= 3) gobusterFlags.push(`--delay ${delayMs}ms`);
  if (userAgent) gobusterFlags.push(`-a "${userAgent}"`);
  const zapConfig = {
    delayInMs: level >= 4 ? 3e3 : level >= 3 ? 1500 : level >= 2 ? 500 : 0,
    threadPerHost: level >= 4 ? 1 : level >= 3 ? 2 : level >= 2 ? 3 : 5,
    maxDuration: level >= 4 ? 120 : level >= 3 ? 90 : 60
  };
  return {
    nuclei: nucleiFlags,
    httpx: httpxFlags,
    naabu: naabuFlags,
    gobuster: gobusterFlags,
    zap: zapConfig
  };
}
function augmentCommandWithEvasion(tool, command, targetProfile) {
  const escalation = targetProfile.evasionEscalation;
  const evasionProfile = getEffectiveEvasionProfile(targetProfile);
  const level = escalation?.currentLevel || 1;
  if (!evasionProfile || level <= 1) {
    return {
      tool,
      originalCommand: command,
      augmentedCommand: command,
      flagsAdded: [],
      evasionLevel: 1
    };
  }
  const flags = buildToolEvasionFlags(evasionProfile, escalation);
  let augmented = command;
  const flagsAdded = [];
  switch (tool) {
    case "nuclei": {
      if (augmented.includes("-rate-limit")) {
        augmented = augmented.replace(/-rate-limit\s+\d+/, `-rate-limit ${evasionProfile.rateLimit}`);
        flagsAdded.push(`-rate-limit ${evasionProfile.rateLimit}`);
      } else {
        augmented += ` -rate-limit ${evasionProfile.rateLimit}`;
        flagsAdded.push(`-rate-limit ${evasionProfile.rateLimit}`);
      }
      for (const hf of flags.nuclei.filter((f) => f.startsWith("-H"))) {
        if (!augmented.includes(hf)) {
          augmented += ` ${hf}`;
          flagsAdded.push(hf);
        }
      }
      break;
    }
    case "httpx": {
      if (augmented.includes("-rate-limit")) {
        augmented = augmented.replace(/-rate-limit\s+\d+/, `-rate-limit ${Math.min(evasionProfile.rateLimit, 50)}`);
      } else {
        augmented += ` -rate-limit ${Math.min(evasionProfile.rateLimit, 50)}`;
      }
      flagsAdded.push(`-rate-limit ${Math.min(evasionProfile.rateLimit, 50)}`);
      for (const hf of flags.httpx.filter((f) => f.startsWith("-H"))) {
        if (!augmented.includes(hf)) {
          augmented += ` ${hf}`;
          flagsAdded.push(hf);
        }
      }
      break;
    }
    case "naabu": {
      if (augmented.includes("-rate ")) {
        augmented = augmented.replace(/-rate\s+\d+/, `-rate ${Math.min(evasionProfile.rateLimit * 10, 1e3)}`);
      }
      flagsAdded.push(`-rate ${Math.min(evasionProfile.rateLimit * 10, 1e3)}`);
      break;
    }
    case "gobuster": {
      if (level >= 2) {
        const threads = Math.max(5, Math.floor(20 / level));
        if (augmented.includes("-t ")) {
          augmented = augmented.replace(/-t\s+\d+/, `-t ${threads}`);
        } else {
          augmented += ` -t ${threads}`;
        }
        flagsAdded.push(`-t ${threads}`);
      }
      if (level >= 3 && !augmented.includes("--delay")) {
        augmented += ` --delay ${evasionProfile.delayMs}ms`;
        flagsAdded.push(`--delay ${evasionProfile.delayMs}ms`);
      }
      break;
    }
  }
  return {
    tool,
    originalCommand: command,
    augmentedCommand: augmented.replace(/\s+/g, " ").trim(),
    flagsAdded,
    evasionLevel: level
  };
}
function getZapEvasionOverrides(targetProfile) {
  const escalation = targetProfile.evasionEscalation;
  const evasionProfile = getEffectiveEvasionProfile(targetProfile);
  const level = escalation?.currentLevel || 1;
  if (!evasionProfile || level <= 1) return null;
  const flags = buildToolEvasionFlags(evasionProfile, escalation);
  return flags.zap;
}
var BROWSER_USER_AGENTS;
var init_evasion_cli_adapter = __esm({
  "server/lib/evasion-cli-adapter.ts"() {
    BROWSER_USER_AGENTS = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ];
  }
});
init_evasion_cli_adapter();
export {
  augmentCommandWithEvasion,
  buildToolEvasionFlags,
  getEffectiveEvasionProfile,
  getZapEvasionOverrides
};
