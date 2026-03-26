/**
 * Ember Agent System — Comprehensive Tests
 *
 * Tests cover:
 *   1. Core library: profiles, capabilities, metadata, payload generation
 *   2. Engagement integration: profile selection, platform detection, safety checks
 *   3. Router: procedure definitions and structure
 *   4. UI routes: sidebar nav entries and App.tsx route registration
 *   5. Database schema: table definitions
 */
import { describe, it, expect } from "vitest";
import path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── Core Library Tests ─────────────────────────────────────────────────────

describe("Ember Agent Core Library", () => {
  it("exports all expected symbols", async () => {
    const mod = await import("./lib/ember-agent-core");
    expect(mod.EMBER_VERSION).toBeDefined();
    expect(mod.EMBER_CODENAME).toBeDefined();
    expect(mod.EMBER_AGENT_TYPE).toBeDefined();
    expect(mod.EMBER_PROFILE_DESCRIPTIONS).toBeDefined();
    expect(mod.EMBER_CAPABILITY_CATALOG).toBeDefined();
    expect(mod.EMBER_CHANNEL_DESCRIPTIONS).toBeDefined();
    expect(mod.EMBER_TRAFFIC_PROFILES).toBeDefined();
    expect(mod.generateEmberPayload).toBeDefined();
    expect(mod.EmberAgentManager).toBeDefined();
    expect(mod.getEmberAgentManager).toBeDefined();
  });

  it("defines 5 agent profiles in EMBER_PROFILE_DESCRIPTIONS", async () => {
    const { EMBER_PROFILE_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    const profileNames = Object.keys(EMBER_PROFILE_DESCRIPTIONS);
    expect(profileNames).toHaveLength(5);
    expect(profileNames).toContain("ghost");
    expect(profileNames).toContain("scout");
    expect(profileNames).toContain("striker");
    expect(profileNames).toContain("sentinel");
    expect(profileNames).toContain("hydra");
  });

  it("each profile description has required fields", async () => {
    const { EMBER_PROFILE_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    for (const [name, profile] of Object.entries(EMBER_PROFILE_DESCRIPTIONS)) {
      expect(profile).toHaveProperty("label");
      expect(profile).toHaveProperty("description");
      expect(profile).toHaveProperty("capabilities");
      expect(profile).toHaveProperty("stealthRating");
      expect(profile).toHaveProperty("footprintKb");
      expect(typeof profile.stealthRating).toBe("number");
      expect(profile.stealthRating).toBeGreaterThan(0);
      expect(profile.stealthRating).toBeLessThanOrEqual(100);
      expect(Array.isArray(profile.capabilities)).toBe(true);
    }
  });

  it("ghost profile has highest stealth rating", async () => {
    const { EMBER_PROFILE_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    const ghost = EMBER_PROFILE_DESCRIPTIONS.ghost;
    expect(ghost.stealthRating).toBeGreaterThanOrEqual(90);
    // Ghost should have highest stealth
    expect(ghost.stealthRating).toBeGreaterThan(EMBER_PROFILE_DESCRIPTIONS.striker.stealthRating);
  });

  it("striker profile has offensive capabilities", async () => {
    const { EMBER_PROFILE_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    const striker = EMBER_PROFILE_DESCRIPTIONS.striker;
    expect(striker.capabilities).toContain("cred_dump");
    expect(striker.capabilities).toContain("lateral_move");
  });

  it("defines at least 30 capabilities in the catalog", async () => {
    const { EMBER_CAPABILITY_CATALOG } = await import("./lib/ember-agent-core");
    expect(EMBER_CAPABILITY_CATALOG.length).toBeGreaterThanOrEqual(30);
  });

  it("each capability has required fields", async () => {
    const { EMBER_CAPABILITY_CATALOG } = await import("./lib/ember-agent-core");
    for (const cap of EMBER_CAPABILITY_CATALOG) {
      expect(cap).toHaveProperty("id");
      expect(cap).toHaveProperty("name");
      expect(cap).toHaveProperty("category");
      expect(cap).toHaveProperty("version");
      expect(cap).toHaveProperty("attackTechniques");
      expect(cap).toHaveProperty("requirements");
      expect(Array.isArray(cap.attackTechniques)).toBe(true);
      expect(Array.isArray(cap.requirements)).toBe(true);
    }
  });

  it("capabilities cover all major categories", async () => {
    const { EMBER_CAPABILITY_CATALOG } = await import("./lib/ember-agent-core");
    const categories = new Set(EMBER_CAPABILITY_CATALOG.map(c => c.category));
    expect(categories.has("recon")).toBe(true);
    expect(categories.has("credential")).toBe(true);
    expect(categories.has("exploit")).toBe(true);
    expect(categories.has("persistence")).toBe(true);
    expect(categories.has("lateral")).toBe(true);
    expect(categories.has("evasion")).toBe(true);
    expect(categories.has("collection")).toBe(true);
    expect(categories.has("exfiltration")).toBe(true);
  });

  it("defines at least 7 communication channels", async () => {
    const { EMBER_CHANNEL_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    const channels = Object.keys(EMBER_CHANNEL_DESCRIPTIONS);
    expect(channels.length).toBeGreaterThanOrEqual(7);
    expect(channels).toContain("https_beacon");
    expect(channels).toContain("dns_covert");
    expect(channels).toContain("doh_tunnel");
    expect(channels).toContain("websocket_stream");
    expect(channels).toContain("steganography");
    expect(channels).toContain("p2p_mesh");
  });

  it("each channel has required fields", async () => {
    const { EMBER_CHANNEL_DESCRIPTIONS } = await import("./lib/ember-agent-core");
    for (const [id, channel] of Object.entries(EMBER_CHANNEL_DESCRIPTIONS)) {
      expect(channel).toHaveProperty("label");
      expect(channel).toHaveProperty("description");
      expect(channel).toHaveProperty("stealthRating");
      expect(channel).toHaveProperty("bandwidth");
      expect(channel).toHaveProperty("latency");
      expect(channel).toHaveProperty("reliability");
    }
  });

  it("EMBER_VERSION is a valid semver-like string", async () => {
    const { EMBER_VERSION } = await import("./lib/ember-agent-core");
    expect(typeof EMBER_VERSION).toBe("string");
    expect(EMBER_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("traffic profiles include realistic mimicry options", async () => {
    const { EMBER_TRAFFIC_PROFILES } = await import("./lib/ember-agent-core");
    expect(EMBER_TRAFFIC_PROFILES.length).toBeGreaterThanOrEqual(3);
    const profileIds = EMBER_TRAFFIC_PROFILES.map(p => p.id);
    // Should have at least one browser-mimicking profile
    const hasBrowserProfile = EMBER_TRAFFIC_PROFILES.some(p =>
      p.name.toLowerCase().includes("chrome") ||
      p.name.toLowerCase().includes("browser") ||
      p.name.toLowerCase().includes("edge")
    );
    expect(hasBrowserProfile).toBe(true);
  });
});

// ─── Payload Generation Tests ───────────────────────────────────────────────

describe("Ember Payload Generation", () => {
  it("generates a bash script payload with all required fields", async () => {
    const { generateEmberPayload } = await import("./lib/ember-agent-core");
    const payload = generateEmberPayload({
      profile: "scout",
      platform: "linux_x64",
      format: "bash_script",
      callback: {
        urls: ["https://c2.example.com/beacon"],
        primaryChannel: "https_beacon",
        fallbackChannels: ["dns_covert"],
      },
      beacon: {
        intervalSeconds: 30,
        jitterPercent: 20,
      },
      evasion: {
        obfuscationLevel: 2,
        stringEncryption: false,
        controlFlowObfuscation: false,
        antiDebugging: false,
        antiVM: false,
        sandboxDetection: false,
        initialSleepMs: 0,
      },
      registrationToken: "test-token-123",
    });

    expect(payload).toHaveProperty("payload");
    expect(payload).toHaveProperty("format", "bash_script");
    expect(payload).toHaveProperty("filename");
    expect(payload).toHaveProperty("hash");
    expect(payload).toHaveProperty("size");
    expect(payload).toHaveProperty("estimatedDetectionRate");
    expect(typeof payload.payload).toBe("string");
    expect(payload.payload.length).toBeGreaterThan(0);
    expect(payload.size).toBeGreaterThan(0);
    expect(payload.estimatedDetectionRate).toBeGreaterThanOrEqual(0);
    expect(payload.estimatedDetectionRate).toBeLessThanOrEqual(100);
  });

  it("generates different payloads for different profiles", async () => {
    const { generateEmberPayload } = await import("./lib/ember-agent-core");
    const baseConfig = {
      platform: "linux_x64" as const,
      format: "bash_script" as const,
      callback: {
        urls: ["https://c2.example.com/beacon"],
        primaryChannel: "https_beacon" as const,
        fallbackChannels: ["dns_covert" as const],
      },
      beacon: { intervalSeconds: 30, jitterPercent: 20 },
      evasion: {
        obfuscationLevel: 2,
        stringEncryption: false,
        controlFlowObfuscation: false,
        antiDebugging: false,
        antiVM: false,
        sandboxDetection: false,
        initialSleepMs: 0,
      },
      registrationToken: "test-token-123",
    };

    const scoutPayload = generateEmberPayload({ ...baseConfig, profile: "scout" });
    const ghostPayload = generateEmberPayload({ ...baseConfig, profile: "ghost" });

    // Different profiles should produce different content
    expect(scoutPayload.payload).not.toBe(ghostPayload.payload);
  });

  it("generates python stager format", async () => {
    const { generateEmberPayload } = await import("./lib/ember-agent-core");
    const payload = generateEmberPayload({
      profile: "scout",
      platform: "linux_x64",
      format: "python_stager",
      callback: {
        urls: ["https://c2.example.com/beacon"],
        primaryChannel: "https_beacon",
        fallbackChannels: [],
      },
      beacon: { intervalSeconds: 30, jitterPercent: 20 },
      evasion: {
        obfuscationLevel: 1,
        stringEncryption: false,
        controlFlowObfuscation: false,
        antiDebugging: false,
        antiVM: false,
        sandboxDetection: false,
        initialSleepMs: 0,
      },
      registrationToken: "test-token-456",
    });

    expect(payload.format).toBe("python_stager");
    expect(payload.payload.toLowerCase()).toContain("python");
  });

  it("generates powershell format for windows", async () => {
    const { generateEmberPayload } = await import("./lib/ember-agent-core");
    const payload = generateEmberPayload({
      profile: "striker",
      platform: "windows_x64",
      format: "powershell_script",
      callback: {
        urls: ["https://c2.example.com/beacon"],
        primaryChannel: "https_beacon",
        fallbackChannels: ["dns_covert"],
      },
      beacon: { intervalSeconds: 15, jitterPercent: 10 },
      evasion: {
        obfuscationLevel: 3,
        stringEncryption: true,
        controlFlowObfuscation: false,
        antiDebugging: true,
        antiVM: true,
        sandboxDetection: true,
        initialSleepMs: 5000,
      },
      registrationToken: "test-token-789",
    });

    expect(payload.format).toBe("powershell_script");
    // PowerShell scripts contain PS-specific cmdlets
    expect(payload.payload).toContain("Set-StrictMode");
  });

  it("generates powershell oneliner format", async () => {
    const { generateEmberPayload } = await import("./lib/ember-agent-core");
    const payload = generateEmberPayload({
      profile: "ghost",
      platform: "windows_x64",
      format: "powershell_oneliner",
      callback: {
        urls: ["https://c2.example.com/beacon"],
        primaryChannel: "https_beacon",
        fallbackChannels: [],
      },
      beacon: { intervalSeconds: 300, jitterPercent: 40 },
      evasion: {
        obfuscationLevel: 5,
        stringEncryption: true,
        controlFlowObfuscation: true,
        antiDebugging: true,
        antiVM: true,
        sandboxDetection: true,
        initialSleepMs: 10000,
      },
      registrationToken: "test-token-oneliner",
    });

    expect(payload.format).toBe("powershell_oneliner");
  });
});

// ─── Agent Manager Tests ────────────────────────────────────────────────────

describe("Ember Agent Manager", () => {
  it("getEmberAgentManager returns a singleton", async () => {
    const { getEmberAgentManager, resetEmberAgentManager } = await import("./lib/ember-agent-core");
    resetEmberAgentManager();
    const mgr1 = getEmberAgentManager();
    const mgr2 = getEmberAgentManager();
    expect(mgr1).toBe(mgr2);
  });

  it("EmberAgentManager class has required methods", async () => {
    const { EmberAgentManager } = await import("./lib/ember-agent-core");
    const mgr = new EmberAgentManager();
    expect(typeof mgr.registerAgent).toBe("function");
    expect(typeof mgr.queueTask).toBe("function");
    expect(typeof mgr.getAgent).toBe("function");
  });
});

// ─── Engagement Integration Tests ───────────────────────────────────────────

describe("Ember Engagement Integration", () => {
  it("exports all integration functions", async () => {
    const mod = await import("./lib/ember-engagement-integration");
    expect(mod.deployEmberAgent).toBeDefined();
    expect(mod.orchestratorDeployEmber).toBeDefined();
    expect(mod.getEmberIntelForEngagement).toBeDefined();
    expect(mod.selectProfile).toBeDefined();
    expect(mod.selectPayloadFormat).toBeDefined();
    expect(mod.selectCapabilities).toBeDefined();
    expect(mod.detectPlatform).toBeDefined();
    expect(mod.checkSafetyForDeployment).toBeDefined();
  });

  it("selectProfile returns sentinel for pentest engagements", async () => {
    const { selectProfile } = await import("./lib/ember-engagement-integration");
    const profile = selectProfile({
      hostname: "target",
      ip: "192.168.1.1",
      platform: "linux",
      arch: "x64",
      shellType: "reverse_shell",
      engagementId: 1,
      engagementType: "pentest",
    });
    expect(profile).toBe("sentinel");
  });

  it("selectProfile returns ghost for EDR-protected targets", async () => {
    const { selectProfile } = await import("./lib/ember-engagement-integration");
    const profile = selectProfile({
      hostname: "target",
      ip: "192.168.1.1",
      platform: "windows",
      arch: "x64",
      shellType: "meterpreter",
      engagementId: 1,
      engagementType: "red_team",
      detectedProducts: ["CrowdStrike Falcon"],
    });
    expect(profile).toBe("ghost");
  });

  it("selectProfile returns hydra for root-level access", async () => {
    const { selectProfile } = await import("./lib/ember-engagement-integration");
    const profile = selectProfile({
      hostname: "target",
      ip: "192.168.1.1",
      platform: "linux",
      arch: "x64",
      shellType: "reverse_shell",
      engagementId: 1,
      engagementType: "red_team",
      privilegeLevel: "root",
    });
    expect(profile).toBe("hydra");
  });

  it("selectProfile returns scout as default for red team", async () => {
    const { selectProfile } = await import("./lib/ember-engagement-integration");
    const profile = selectProfile({
      hostname: "target",
      ip: "192.168.1.1",
      platform: "linux",
      arch: "x64",
      shellType: "reverse_shell",
      engagementId: 1,
      engagementType: "red_team",
    });
    expect(profile).toBe("scout");
  });

  it("detectPlatform maps correctly", async () => {
    const { detectPlatform } = await import("./lib/ember-engagement-integration");

    expect(detectPlatform({
      hostname: "h", ip: "1.1.1.1", platform: "linux", arch: "x64",
      shellType: "reverse_shell", engagementId: 1, engagementType: "red_team",
    })).toBe("linux_x64");

    expect(detectPlatform({
      hostname: "h", ip: "1.1.1.1", platform: "windows", arch: "x86",
      shellType: "reverse_shell", engagementId: 1, engagementType: "red_team",
    })).toBe("windows_x86");

    expect(detectPlatform({
      hostname: "h", ip: "1.1.1.1", platform: "macos", arch: "arm64",
      shellType: "reverse_shell", engagementId: 1, engagementType: "red_team",
    })).toBe("macos_arm64");
  });

  it("selectPayloadFormat returns bash_script for linux", async () => {
    const { selectPayloadFormat } = await import("./lib/ember-engagement-integration");
    const format = selectPayloadFormat({
      hostname: "target", ip: "1.1.1.1", platform: "linux", arch: "x64",
      shellType: "reverse_shell", engagementId: 1, engagementType: "red_team",
    });
    expect(format).toBe("bash_script");
  });

  it("selectPayloadFormat returns powershell_script for windows meterpreter", async () => {
    const { selectPayloadFormat } = await import("./lib/ember-engagement-integration");
    const format = selectPayloadFormat({
      hostname: "target", ip: "1.1.1.1", platform: "windows", arch: "x64",
      shellType: "meterpreter", engagementId: 1, engagementType: "red_team",
    });
    expect(format).toBe("powershell_script");
  });

  it("selectCapabilities includes offensive caps for red team", async () => {
    const { selectCapabilities } = await import("./lib/ember-engagement-integration");
    const caps = selectCapabilities({
      hostname: "target", ip: "1.1.1.1", platform: "linux", arch: "x64",
      shellType: "reverse_shell", engagementId: 1, engagementType: "red_team",
    });
    expect(caps).toContain("system_survey");
    expect(caps).toContain("network_scan");
    expect(caps).toContain("credential_harvest");
    expect(caps).toContain("lateral_movement");
  });

  it("selectCapabilities uses collection caps for pentest", async () => {
    const { selectCapabilities } = await import("./lib/ember-engagement-integration");
    const caps = selectCapabilities({
      hostname: "target", ip: "1.1.1.1", platform: "linux", arch: "x64",
      shellType: "reverse_shell", engagementId: 1, engagementType: "pentest",
    });
    expect(caps).toContain("system_survey");
    expect(caps).toContain("screenshot");
    expect(caps).toContain("file_search");
    expect(caps).not.toContain("credential_harvest");
  });
});

// ─── Router Tests ───────────────────────────────────────────────────────────

describe("Ember Agent Router", () => {
  it("exports emberAgentRouter", async () => {
    const mod = await import("./routers/ember-agent");
    expect(mod.emberAgentRouter).toBeDefined();
    expect(mod.emberAgentRouter._def).toBeDefined();
  });

  it("has all required procedures", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures).toContain("getMetadata");
    expect(procedures).toContain("getFleetOverview");
    expect(procedures).toContain("listAgents");
    expect(procedures).toContain("getAgent");
    expect(procedures).toContain("generatePayload");
    expect(procedures).toContain("listPayloads");
    expect(procedures).toContain("queueTask");
    expect(procedures).toContain("getAgentTasks");
    expect(procedures).toContain("processBeacon");
    expect(procedures).toContain("deployAgent");
    expect(procedures).toContain("terminateAgent");
    expect(procedures).toContain("createSwarm");
    expect(procedures).toContain("listSwarms");
    expect(procedures).toContain("getIntelligence");
  });

  it("has at least 15 procedures", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures.length).toBeGreaterThanOrEqual(15);
  });
});

// ─── UI Route & Navigation Tests ────────────────────────────────────────────

describe("Ember UI Routes and Navigation", () => {
  it("sidebar-nav includes unified Agent Management group with Ember and all C2 frameworks", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(content).toContain("agent-management");
    expect(content).toContain("Agent Management");
    expect(content).toContain("Ember Fleet");
    expect(content).toContain("Ember Deploy");
    expect(content).toContain("Ember Tasks");
    expect(content).toContain("Ember Payloads");
    expect(content).toContain("Ember Swarm");
    expect(content).toContain("Ember Intelligence");
    expect(content).toContain("Ember Capabilities");
    expect(content).toContain("Ember Cognitive");
    // C2 frameworks consolidated under Agent Management
    expect(content).toContain("Sliver C2");
    expect(content).toContain("MSF Servers");
    expect(content).toContain("MSF Sessions");
    expect(content).toContain("C2 Command Center");
  });

  it("sidebar-nav grants Agent Management access to operator and team_lead", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    // operator role should have c2-agents access in the ROLE_GROUP_ACCESS (renamed from agent-management)
    expect(content).toContain("c2-agents");
    // Extract the operator block (multi-line array)
    const operatorMatch = content.match(/operator:\s*\[([\s\S]*?)\]/)?.[1] ?? '';
    expect(operatorMatch).toContain("c2-agents");
    // team_lead role should have c2-agents access
    const teamLeadMatch = content.match(/team_lead:\s*\[([\s\S]*?)\]/)?.[1] ?? '';
    expect(teamLeadMatch).toContain("c2-agents");
  });

  it("App.tsx registers all Ember routes", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/App.tsx"),
      "utf-8"
    );
    expect(content).toContain("EmberFleetOverview");
    expect(content).toContain("EmberDeploy");
    expect(content).toContain("EmberTaskConsole");
    expect(content).toContain("EmberPayloadArmory");
    expect(content).toContain("EmberSwarmControl");
    expect(content).toContain("EmberIntelligence");
    expect(content).toContain("EmberCapabilities");
    expect(content).toContain("EmberCognitiveEngine");
    expect(content).toContain('path="/ember"');
    expect(content).toContain('path="/ember/deploy"');
    expect(content).toContain('path="/ember/tasks"');
    expect(content).toContain('path="/ember/payloads"');
    expect(content).toContain('path="/ember/swarm"');
    expect(content).toContain('path="/ember/intelligence"');
    expect(content).toContain('path="/ember/capabilities"');
    expect(content).toContain('path="/ember/cognitive"');
  });

  it("all Ember page files exist", async () => {
    const fs = await import("fs");
    const pages = [
      "EmberFleetOverview",
      "EmberDeploy",
      "EmberTaskConsole",
      "EmberPayloadArmory",
      "EmberSwarmControl",
      "EmberIntelligence",
      "EmberCapabilities",
      "EmberCognitiveEngine",
    ];
    for (const page of pages) {
      const exists = fs.existsSync(
        path.join(PROJECT_ROOT, `client/src/pages/${page}.tsx`)
      );
      expect(exists, `${page}.tsx should exist`).toBe(true);
    }
  });
});

// ─── Database Schema Tests ──────────────────────────────────────────────────

describe("Ember Database Schema", () => {
  it("schema defines all Ember tables", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "drizzle/schema.ts"),
      "utf-8"
    );
    expect(content).toContain("emberAgents");
    expect(content).toContain("emberTasks");
    expect(content).toContain("emberPayloads");
    expect(content).toContain("emberIntelligence");
    expect(content).toContain("emberSwarms");
    expect(content).toContain("emberBeacons");
  });

  it("emberAgents table has required columns", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "drizzle/schema.ts"),
      "utf-8"
    );
    expect(content).toContain("agentId");
    expect(content).toContain("profile");
    expect(content).toContain("platform");
    expect(content).toContain("hostname");
    expect(content).toContain("beaconInterval");
    expect(content).toContain("autonomy");
    expect(content).toContain("engagementId");
  });
});


// ─── Ember Integration in Agents & Agent Manager Pages ──────────────────

describe("Ember Integration in Agents Page", () => {
  it("Agents page imports ember tRPC hooks", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/Agents.tsx"), "utf-8");
    expect(content).toContain("trpc.ember");
    expect(content).toContain("Ember");
  });

  it("Agents page has Ember Implants tab", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/Agents.tsx"), "utf-8");
    expect(content).toContain("Ember Implants");
    expect(content).toContain('value="ember"');
  });

  it("Agents page shows Ember agent state and profile badges", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/Agents.tsx"), "utf-8");
    expect(content).toContain("EMBER_STATE_COLORS");
    expect(content).toContain("EMBER_PROFILE_COLORS");
    expect(content).toContain("ghost");
    expect(content).toContain("scout");
    expect(content).toContain("striker");
  });

  it("Agents page has unified stats for both Caldera and Ember", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/Agents.tsx"), "utf-8");
    expect(content).toContain("Caldera Agents");
    expect(content).toContain("Ember Implants");
    expect(content).toContain('value="caldera"');
    expect(content).toContain('value="ember"');
  });

  it("Agents page has kill action for Ember agents", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/Agents.tsx"), "utf-8");
    expect(content).toContain("killAgent");
    expect(content).toContain("Kill Ember Implant");
  });
});

describe("Ember Integration in Agent Manager Page", () => {
  it("Agent Manager has Ember Implants tab", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/AgentManager.tsx"), "utf-8");
    expect(content).toContain("Ember Implants");
    expect(content).toContain('value="ember"');
  });

  it("Agent Manager has EmberImplantTab component", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/AgentManager.tsx"), "utf-8");
    expect(content).toContain("function EmberImplantTab");
    expect(content).toContain("<EmberImplantTab />");
  });

  it("Agent Manager Ember tab shows stats and evasion indicators", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/AgentManager.tsx"), "utf-8");
    expect(content).toContain("Total Implants");
    expect(content).toContain("Cognitive");
    expect(content).toContain("memoryEncryption");
    expect(content).toContain("edrEvasion");
  });

  it("Agent Manager Ember tab has deploy and fleet overview links", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/AgentManager.tsx"), "utf-8");
    expect(content).toContain('href="/ember/deploy"');
    expect(content).toContain('href="/ember"');
    expect(content).toContain("Deploy Ember");
  });
});

describe("Ember Router Aliases", () => {
  it("ember router has getDashboard alias", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures).toContain("getDashboard");
  });

  it("ember router has killAgent alias", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures).toContain("killAgent");
  });

  it("ember router has getAgentDetail alias", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures).toContain("getAgentDetail");
  });

  it("ember router has issueTask alias", async () => {
    const mod = await import("./routers/ember-agent");
    const procedures = Object.keys(mod.emberAgentRouter._def.procedures);
    expect(procedures).toContain("issueTask");
  });
});
