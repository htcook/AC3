/**
 * Ember Interception Detection Knowledge Module
 * ═══════════════════════════════════════════════════════════════════════
 * Integrates the interception fingerprinting engine with Ember agent
 * operations. Provides real-time EDR/AV detection, adaptive evasion
 * selection, and OPSEC scoring adjustments based on detected defenses.
 *
 * This module bridges:
 *   - Interception Fingerprint Engine → Ember Agent Config
 *   - DI Scan Results → Ember Pre-deployment Intelligence
 *   - Live Agent Telemetry → Continuous Evasion Adaptation
 *
 * Key capabilities:
 *   1. Pre-deployment defense profiling from DI scan data
 *   2. Runtime fingerprinting from agent process/service enumeration
 *   3. Adaptive evasion module selection based on detected products
 *   4. OPSEC score adjustments based on defense posture
 *   5. C2 channel recommendations based on network monitoring
 *   6. Payload recommendations based on endpoint protection
 */

import type {
  InterceptionReport,
  InterceptionFinding,
  InterceptionDomain,
  EvasionTechnique,
  EvasionStrategy,
  FingerprintInput,
} from "./interception-fingerprint-engine";
import {
  fingerprintInterceptions,
  buildFingerprintInputFromDIScan,
  buildFingerprintInputFromEngagement,
} from "./interception-fingerprint-engine";

// ─── Types ──────────────────────────────────────────────────────────

export interface EmberDefenseProfile {
  /** Unique profile ID */
  profileId: string;
  /** Target host or domain */
  target: string;
  /** When this profile was generated */
  generatedAt: number;
  /** Source of the intelligence */
  source: "di_scan" | "agent_recon" | "engagement_data" | "manual";
  /** Full interception report */
  report: InterceptionReport;
  /** Recommended Ember configuration overrides */
  emberConfigOverrides: EmberConfigOverrides;
  /** OPSEC risk assessment */
  opsecAssessment: OpsecAssessment;
  /** C2 channel recommendations */
  c2Recommendations: C2Recommendation[];
  /** Payload recommendations */
  payloadRecommendations: PayloadRecommendation[];
  /** Persistence recommendations */
  persistenceRecommendations: PersistenceRecommendation[];
}

export interface EmberConfigOverrides {
  /** Override evasion settings based on detected defenses */
  evasion: {
    memoryEncryption: boolean;
    sleepObfuscation: boolean;
    processMasquerade: boolean;
    masqueradeProcess?: string;
    trafficMimicry: boolean;
    trafficProfile?: string;
    antiForensics: boolean;
    sandboxDetection: boolean;
    edrEvasion: boolean;
  };
  /** Recommended capability modules to load/avoid */
  capabilities: {
    required: string[];
    recommended: string[];
    avoid: string[];
    loadOrder: string[];
  };
  /** Beacon timing adjustments */
  beacon: {
    minInterval: number;
    maxInterval: number;
    jitterPercent: number;
    rationale: string;
  };
}

export interface OpsecAssessment {
  /** Overall OPSEC risk score (0-100, higher = more risk) */
  riskScore: number;
  /** Risk band */
  riskBand: "critical" | "high" | "medium" | "low";
  /** Key risk factors */
  factors: Array<{
    factor: string;
    severity: "critical" | "high" | "medium" | "low";
    description: string;
    mitigation: string;
  }>;
  /** Recommended OPSEC posture */
  recommendedPosture: "ghost" | "stealth" | "balanced" | "aggressive";
}

export interface C2Recommendation {
  protocol: string;
  rationale: string;
  risk: "low" | "medium" | "high";
  configuration: Record<string, any>;
}

export interface PayloadRecommendation {
  type: string;
  format: string;
  rationale: string;
  evasionTechniques: string[];
  risk: "low" | "medium" | "high";
}

export interface PersistenceRecommendation {
  method: string;
  rationale: string;
  risk: "low" | "medium" | "high";
  survivesReboot: boolean;
  detectionLikelihood: "low" | "medium" | "high";
}

// ─── EDR/AV → Ember Evasion Mapping ────────────────────────────────

/** Maps detected security products to specific Ember evasion configurations */
const PRODUCT_EVASION_MAP: Record<string, Partial<EmberConfigOverrides["evasion"]>> = {
  // EDR products that require maximum evasion
  "CrowdStrike Falcon": {
    memoryEncryption: true,
    sleepObfuscation: true,
    processMasquerade: true,
    masqueradeProcess: "svchost.exe",
    edrEvasion: true,
    antiForensics: true,
  },
  "Microsoft Defender for Endpoint": {
    memoryEncryption: true,
    sleepObfuscation: true,
    processMasquerade: true,
    masqueradeProcess: "RuntimeBroker.exe",
    edrEvasion: true,
    sandboxDetection: true,
  },
  "SentinelOne Singularity": {
    memoryEncryption: true,
    sleepObfuscation: true,
    processMasquerade: true,
    masqueradeProcess: "dllhost.exe",
    edrEvasion: true,
    antiForensics: true,
  },
  "Carbon Black": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    processMasquerade: true,
    masqueradeProcess: "conhost.exe",
  },
  "Cortex XDR": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    processMasquerade: true,
    masqueradeProcess: "SearchProtocolHost.exe",
    antiForensics: true,
  },
  "Elastic Endpoint Security": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    antiForensics: true,
  },
  "Symantec Endpoint Protection": {
    memoryEncryption: true,
    edrEvasion: true,
    processMasquerade: true,
    masqueradeProcess: "wmiprvse.exe",
  },
  "Trend Micro Apex One": {
    memoryEncryption: true,
    edrEvasion: true,
    sandboxDetection: true,
  },
  "Sophos Intercept X": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    antiForensics: true,
  },
  "Cybereason": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    processMasquerade: true,
    masqueradeProcess: "taskhost.exe",
  },
  "Cylance": {
    memoryEncryption: true,
    edrEvasion: true,
    sandboxDetection: true,
  },
  "ESET Endpoint Security": {
    memoryEncryption: true,
    edrEvasion: true,
  },
  "Kaspersky Endpoint Security": {
    memoryEncryption: true,
    sleepObfuscation: true,
    edrEvasion: true,
    sandboxDetection: true,
  },
  "Bitdefender GravityZone": {
    memoryEncryption: true,
    edrEvasion: true,
    sandboxDetection: true,
  },
  "F-Secure": {
    memoryEncryption: true,
    edrEvasion: true,
  },
};

/** Maps detected network monitoring to C2 recommendations */
const NETWORK_MONITORING_C2_MAP: Record<string, C2Recommendation[]> = {
  "ssl_inspection": [
    {
      protocol: "domain_fronting",
      rationale: "SSL inspection detected — use domain fronting to hide C2 within legitimate TLS sessions",
      risk: "medium",
      configuration: { frontDomain: "cdn.example.com", useAzureCDN: true },
    },
    {
      protocol: "dns_over_https",
      rationale: "DNS-over-HTTPS bypasses SSL inspection for C2 channel",
      risk: "low",
      configuration: { resolver: "cloudflare-dns.com", recordType: "TXT" },
    },
  ],
  "ids_inline": [
    {
      protocol: "https_custom",
      rationale: "IDS/IPS detected — use custom HTTPS with traffic mimicry to avoid signature detection",
      risk: "medium",
      configuration: { mimicProfile: "chrome_browsing", jitter: 0.3 },
    },
    {
      protocol: "websocket",
      rationale: "WebSocket connections often bypass IDS signature matching",
      risk: "low",
      configuration: { path: "/api/v2/stream", upgradeHeader: true },
    },
  ],
  "proxy_intercept": [
    {
      protocol: "https_pinned",
      rationale: "Transparent proxy detected — use certificate pinning to detect MitM",
      risk: "high",
      configuration: { pinCert: true, fallbackDNS: true },
    },
  ],
  "traffic_mirror": [
    {
      protocol: "steganography",
      rationale: "Traffic mirroring detected — embed C2 data in legitimate-looking traffic",
      risk: "low",
      configuration: { carrier: "image_uploads", encoding: "lsb" },
    },
  ],
};

// ─── Core Functions ─────────────────────────────────────────────────

/**
 * Generate an Ember defense profile from DI scan data.
 * Called before agent deployment to pre-configure evasion based on known defenses.
 */
export function generateDefenseProfileFromDIScan(data: {
  assets?: any[];
  scan?: any;
  target?: string;
}): EmberDefenseProfile {
  const fpInput = buildFingerprintInputFromDIScan(data);
  const report = fingerprintInterceptions(fpInput);
  return buildDefenseProfile(report, data.target || data.scan?.primaryDomain || "unknown", "di_scan");
}

/**
 * Generate an Ember defense profile from engagement attack graph data.
 */
export function generateDefenseProfileFromEngagement(data: {
  nodes?: any[];
  edges?: any[];
  target?: string;
}): EmberDefenseProfile {
  const fpInput = buildFingerprintInputFromEngagement(data);
  const report = fingerprintInterceptions(fpInput);
  return buildDefenseProfile(report, data.target || "unknown", "engagement_data");
}

/**
 * Generate an Ember defense profile from live agent telemetry.
 * Called when an Ember agent reports process/service enumeration results.
 */
export function generateDefenseProfileFromAgentRecon(input: FingerprintInput): EmberDefenseProfile {
  const report = fingerprintInterceptions(input);
  return buildDefenseProfile(report, input.target || "unknown", "agent_recon");
}

/**
 * Get adaptive evasion recommendations for a specific Ember capability module.
 * Returns evasion techniques that should be applied before executing the module.
 */
export function getModuleEvasionRecommendations(
  profile: EmberDefenseProfile,
  moduleId: string
): {
  preExecutionSteps: string[];
  runtimeAdjustments: Record<string, any>;
  postExecutionCleanup: string[];
  risk: "low" | "medium" | "high" | "critical";
} {
  const findings = profile.report.findings;
  const preSteps: string[] = [];
  const cleanup: string[] = [];
  const adjustments: Record<string, any> = {};
  let maxRisk: "low" | "medium" | "high" | "critical" = "low";

  // Check for EDR that monitors specific module behaviors
  for (const finding of findings) {
    if (finding.domain === "endpoint") {
      // EDR detected — apply pre-execution evasion
      if (moduleId.includes("recon") || moduleId.includes("discovery")) {
        preSteps.push(`Unhook ${finding.vendor} userland hooks before enumeration`);
        preSteps.push("Use direct syscalls for process/service enumeration");
        adjustments.useSyscalls = true;
        adjustments.unhookFirst = true;
        maxRisk = "high";
      }
      if (moduleId.includes("credential") || moduleId.includes("mimikatz")) {
        preSteps.push(`Patch ${finding.vendor} AMSI provider before credential access`);
        preSteps.push("Use in-memory-only credential extraction");
        preSteps.push("Avoid touching LSASS directly — use SSP injection or DCSync");
        adjustments.avoidLsass = true;
        adjustments.patchAmsi = true;
        maxRisk = "critical";
      }
      if (moduleId.includes("lateral") || moduleId.includes("pivot")) {
        preSteps.push("Use WMI or DCOM for lateral movement (less monitored than PSExec)");
        preSteps.push(`Check ${finding.vendor} network monitoring before pivoting`);
        adjustments.preferWmi = true;
        maxRisk = "high";
      }
      if (moduleId.includes("persist")) {
        preSteps.push("Use COM hijacking or DLL search order hijacking for persistence");
        preSteps.push(`Avoid registry Run keys — monitored by ${finding.vendor}`);
        adjustments.avoidRegistryRun = true;
        maxRisk = "high";
      }
      if (moduleId.includes("exfil")) {
        preSteps.push("Use DNS exfiltration or steganography to avoid DLP");
        preSteps.push("Chunk data into small packets with jitter");
        adjustments.chunkSize = 512;
        adjustments.useEncryption = true;
        maxRisk = "high";
      }
    }

    if (finding.domain === "host") {
      // Host monitoring detected
      if (moduleId.includes("evasion.log_cleaner")) {
        preSteps.push(`${finding.vendor} detected — clear specific event IDs only`);
        cleanup.push("Restore original log timestamps after clearing");
        maxRisk = "medium";
      }
      if (moduleId.includes("evasion.timestomp")) {
        preSteps.push("Use $MFT manipulation instead of SetFileTime API");
        adjustments.useMftManipulation = true;
        maxRisk = "medium";
      }
    }

    if (finding.domain === "network") {
      // Network monitoring detected
      if (moduleId.includes("c2") || moduleId.includes("beacon")) {
        preSteps.push(`${finding.vendor} monitoring network — use encrypted channel`);
        adjustments.forceEncryption = true;
        adjustments.useJitter = true;
        maxRisk = "high";
      }
    }
  }

  // Post-execution cleanup for all modules
  if (findings.some(f => f.domain === "endpoint")) {
    cleanup.push("Re-hook any patched API hooks to avoid detection of tampering");
    cleanup.push("Clear any artifacts from temp directories");
  }
  if (findings.some(f => f.domain === "host" && f.category === "sysmon")) {
    cleanup.push("Sysmon detected — clear relevant event IDs (1, 3, 7, 8, 10, 11)");
  }

  return {
    preExecutionSteps: preSteps,
    runtimeAdjustments: adjustments,
    postExecutionCleanup: cleanup,
    risk: maxRisk,
  };
}

/**
 * Calculate OPSEC score adjustment based on defense profile.
 * Returns a modifier that should be applied to the base OPSEC score.
 */
export function calculateOpsecAdjustment(profile: EmberDefenseProfile): {
  scoreModifier: number;
  rationale: string;
  recommendations: string[];
} {
  const findings = profile.report.findings;
  let modifier = 0;
  const recommendations: string[] = [];

  // EDR presence increases OPSEC risk significantly
  const edrFindings = findings.filter(f => f.domain === "endpoint" && f.confidence.score > 0.6);
  if (edrFindings.length > 0) {
    modifier += edrFindings.length * 15;
    recommendations.push(`${edrFindings.length} endpoint protection product(s) detected — increase beacon interval and reduce tool execution frequency`);
  }

  // Host monitoring adds moderate risk
  const hostFindings = findings.filter(f => f.domain === "host" && f.confidence.score > 0.5);
  if (hostFindings.length > 0) {
    modifier += hostFindings.length * 8;
    recommendations.push(`${hostFindings.length} host monitoring tool(s) detected — use living-off-the-land techniques`);
  }

  // Network monitoring adds risk to C2 operations
  const netFindings = findings.filter(f => f.domain === "network" && f.confidence.score > 0.5);
  if (netFindings.length > 0) {
    modifier += netFindings.length * 10;
    recommendations.push(`${netFindings.length} network monitoring tool(s) detected — use encrypted C2 with traffic mimicry`);
  }

  // High-confidence findings are more impactful
  const highConfFindings = findings.filter(f => f.confidence.score > 0.8);
  if (highConfFindings.length > 0) {
    modifier += highConfFindings.length * 5;
  }

  return {
    scoreModifier: Math.min(modifier, 50), // Cap at 50 points
    rationale: `Defense profile analysis: ${findings.length} security products detected (${edrFindings.length} EDR, ${hostFindings.length} host, ${netFindings.length} network)`,
    recommendations,
  };
}

// ─── Internal Helpers ───────────────────────────────────────────────

function buildDefenseProfile(
  report: InterceptionReport,
  target: string,
  source: EmberDefenseProfile["source"]
): EmberDefenseProfile {
  const profileId = `edp-${target.replace(/[^a-zA-Z0-9]/g, "-")}-${Date.now()}`;

  // Build Ember config overrides from detected products
  const evasionOverrides = buildEvasionOverrides(report.findings);
  const capabilityOverrides = buildCapabilityOverrides(report.findings);
  const beaconOverrides = buildBeaconOverrides(report.findings);
  const opsecAssessment = buildOpsecAssessment(report);
  const c2Recs = buildC2Recommendations(report.findings);
  const payloadRecs = buildPayloadRecommendations(report.findings);
  const persistenceRecs = buildPersistenceRecommendations(report.findings);

  return {
    profileId,
    target,
    generatedAt: Date.now(),
    source,
    report,
    emberConfigOverrides: {
      evasion: evasionOverrides,
      capabilities: capabilityOverrides,
      beacon: beaconOverrides,
    },
    opsecAssessment,
    c2Recommendations: c2Recs,
    payloadRecommendations: payloadRecs,
    persistenceRecommendations: persistenceRecs,
  };
}

function buildEvasionOverrides(findings: InterceptionFinding[]): EmberConfigOverrides["evasion"] {
  // Start with conservative defaults
  const overrides: EmberConfigOverrides["evasion"] = {
    memoryEncryption: false,
    sleepObfuscation: false,
    processMasquerade: false,
    trafficMimicry: false,
    antiForensics: false,
    sandboxDetection: false,
    edrEvasion: false,
  };

  // Apply product-specific overrides
  for (const finding of findings) {
    const productKey = `${finding.vendor} ${finding.product}`;
    const productOverrides = PRODUCT_EVASION_MAP[productKey];
    if (productOverrides) {
      Object.assign(overrides, productOverrides);
    }
  }

  // If any EDR is detected, ensure minimum evasion
  if (findings.some(f => f.domain === "endpoint")) {
    overrides.memoryEncryption = true;
    overrides.edrEvasion = true;
  }

  // If network monitoring detected, enable traffic mimicry
  if (findings.some(f => f.domain === "network")) {
    overrides.trafficMimicry = true;
    overrides.trafficProfile = overrides.trafficProfile || "chrome_browsing";
  }

  // If host monitoring detected, enable anti-forensics
  if (findings.some(f => f.domain === "host")) {
    overrides.antiForensics = true;
  }

  return overrides;
}

function buildCapabilityOverrides(findings: InterceptionFinding[]): EmberConfigOverrides["capabilities"] {
  const required: string[] = [];
  const recommended: string[] = [];
  const avoid: string[] = [];
  const loadOrder: string[] = [];

  // Always require evasion adapter when defenses detected
  if (findings.length > 0) {
    required.push("ember.cognitive.evasion_adapter");
    loadOrder.push("ember.cognitive.evasion_adapter");
  }

  // EDR-specific module recommendations
  const hasEdr = findings.some(f => f.domain === "endpoint");
  if (hasEdr) {
    required.push("ember.evasion.amsi_bypass");
    required.push("ember.evasion.etw_patch");
    recommended.push("ember.evasion.log_cleaner");
    recommended.push("ember.evasion.timestomp");
    // Load evasion modules first
    loadOrder.unshift("ember.evasion.amsi_bypass", "ember.evasion.etw_patch");
    // Avoid noisy modules
    avoid.push("ember.recon.port_scanner"); // Use passive recon instead
  }

  // Sysmon-specific
  if (findings.some(f => f.category === "sysmon")) {
    required.push("ember.evasion.log_cleaner");
    recommended.push("ember.evasion.timestomp");
  }

  // Network monitoring — avoid direct network tools
  if (findings.some(f => f.domain === "network" && f.category === "ids_ips")) {
    avoid.push("ember.recon.port_scanner");
    recommended.push("ember.recon.service_fingerprint"); // Passive fingerprinting
  }

  return { required, recommended, avoid, loadOrder };
}

function buildBeaconOverrides(findings: InterceptionFinding[]): EmberConfigOverrides["beacon"] {
  const edrCount = findings.filter(f => f.domain === "endpoint").length;
  const netMonCount = findings.filter(f => f.domain === "network").length;

  // More defenses = slower, more jittery beacons
  if (edrCount >= 2 || netMonCount >= 2) {
    return {
      minInterval: 300000,  // 5 minutes minimum
      maxInterval: 900000,  // 15 minutes maximum
      jitterPercent: 40,
      rationale: `Heavy defense posture detected (${edrCount} EDR, ${netMonCount} network) — using slow beacon with high jitter`,
    };
  }
  if (edrCount >= 1 || netMonCount >= 1) {
    return {
      minInterval: 120000,  // 2 minutes
      maxInterval: 600000,  // 10 minutes
      jitterPercent: 30,
      rationale: `Moderate defense posture (${edrCount} EDR, ${netMonCount} network) — using moderate beacon timing`,
    };
  }
  return {
    minInterval: 30000,   // 30 seconds
    maxInterval: 120000,  // 2 minutes
    jitterPercent: 20,
    rationale: "Minimal defenses detected — using standard beacon timing",
  };
}

function buildOpsecAssessment(report: InterceptionReport): OpsecAssessment {
  const findings = report.findings;
  const factors: OpsecAssessment["factors"] = [];
  let riskScore = 0;

  // Endpoint protection
  const edrFindings = findings.filter(f => f.domain === "endpoint");
  for (const f of edrFindings) {
    const severity = f.confidence.score > 0.8 ? "critical" as const : f.confidence.score > 0.5 ? "high" as const : "medium" as const;
    riskScore += severity === "critical" ? 25 : severity === "high" ? 15 : 8;
    factors.push({
      factor: `${f.vendor} ${f.product} (endpoint)`,
      severity,
      description: f.summary,
      mitigation: f.opsecRecommendations[0] || "Apply standard EDR evasion techniques",
    });
  }

  // Host monitoring
  const hostFindings = findings.filter(f => f.domain === "host");
  for (const f of hostFindings) {
    riskScore += f.confidence.score > 0.7 ? 12 : 6;
    factors.push({
      factor: `${f.vendor} ${f.product} (host)`,
      severity: f.confidence.score > 0.7 ? "high" : "medium",
      description: f.summary,
      mitigation: f.opsecRecommendations[0] || "Use living-off-the-land techniques",
    });
  }

  // Network monitoring
  const netFindings = findings.filter(f => f.domain === "network");
  for (const f of netFindings) {
    riskScore += f.confidence.score > 0.7 ? 15 : 8;
    factors.push({
      factor: `${f.vendor} ${f.product} (network)`,
      severity: f.confidence.score > 0.7 ? "high" : "medium",
      description: f.summary,
      mitigation: f.opsecRecommendations[0] || "Use encrypted C2 with traffic mimicry",
    });
  }

  riskScore = Math.min(riskScore, 100);
  const riskBand = riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low";
  const recommendedPosture = riskScore >= 75 ? "ghost" : riskScore >= 50 ? "stealth" : riskScore >= 25 ? "balanced" : "aggressive";

  return { riskScore, riskBand, factors, recommendedPosture };
}

function buildC2Recommendations(findings: InterceptionFinding[]): C2Recommendation[] {
  const recs: C2Recommendation[] = [];
  const seen = new Set<string>();

  for (const finding of findings) {
    if (finding.domain !== "network") continue;
    const tapType = finding.category;
    const c2Recs = NETWORK_MONITORING_C2_MAP[tapType];
    if (c2Recs) {
      for (const rec of c2Recs) {
        if (!seen.has(rec.protocol)) {
          seen.add(rec.protocol);
          recs.push(rec);
        }
      }
    }
  }

  // Default recommendation if no specific network monitoring detected
  if (recs.length === 0) {
    recs.push({
      protocol: "https",
      rationale: "No specific network monitoring detected — standard HTTPS C2 is sufficient",
      risk: "low",
      configuration: { useJitter: true, mimicProfile: "chrome_browsing" },
    });
  }

  return recs;
}

function buildPayloadRecommendations(findings: InterceptionFinding[]): PayloadRecommendation[] {
  const recs: PayloadRecommendation[] = [];
  const hasEdr = findings.some(f => f.domain === "endpoint");
  const hasAmsi = findings.some(f => f.category === "amsi" || f.product.toLowerCase().includes("amsi"));

  if (hasEdr) {
    recs.push({
      type: "shellcode_loader",
      format: "reflective_dll",
      rationale: "EDR detected — use reflective DLL injection to avoid on-disk detection",
      evasionTechniques: ["memory_encryption", "sleep_obfuscation", "syscall_unhooking"],
      risk: "medium",
    });
    recs.push({
      type: "living_off_the_land",
      format: "powershell_cradle",
      rationale: "Use LOLBins to blend with legitimate system activity",
      evasionTechniques: ["amsi_bypass", "etw_patch", "script_block_logging_bypass"],
      risk: "low",
    });
  }

  if (hasAmsi) {
    recs.push({
      type: "amsi_bypass_first",
      format: "staged",
      rationale: "AMSI detected — bypass AMSI before loading main payload",
      evasionTechniques: ["amsi_patch", "amsi_provider_unload", "clm_bypass"],
      risk: "medium",
    });
  }

  if (!hasEdr) {
    recs.push({
      type: "standard",
      format: "exe",
      rationale: "No EDR detected — standard executable payload is acceptable",
      evasionTechniques: ["basic_obfuscation"],
      risk: "low",
    });
  }

  return recs;
}

function buildPersistenceRecommendations(findings: InterceptionFinding[]): PersistenceRecommendation[] {
  const recs: PersistenceRecommendation[] = [];
  const hasEdr = findings.some(f => f.domain === "endpoint");
  const hasSysmon = findings.some(f => f.category === "sysmon");
  const hasFim = findings.some(f => f.category === "fim");

  if (hasEdr) {
    recs.push({
      method: "com_hijack",
      rationale: "EDR detected — COM hijacking is less monitored than registry Run keys",
      risk: "medium",
      survivesReboot: true,
      detectionLikelihood: "low",
    });
    recs.push({
      method: "dll_search_order_hijack",
      rationale: "DLL search order hijacking blends with legitimate DLL loading",
      risk: "medium",
      survivesReboot: true,
      detectionLikelihood: "low",
    });
  }

  if (hasSysmon) {
    recs.push({
      method: "wmi_subscription",
      rationale: "Sysmon detected — WMI event subscriptions are harder to detect with default Sysmon config",
      risk: "medium",
      survivesReboot: true,
      detectionLikelihood: "medium",
    });
  }

  if (hasFim) {
    recs.push({
      method: "memory_only",
      rationale: "FIM detected — avoid writing persistence to monitored file paths",
      risk: "low",
      survivesReboot: false,
      detectionLikelihood: "low",
    });
  }

  if (!hasEdr && !hasSysmon && !hasFim) {
    recs.push({
      method: "scheduled_task",
      rationale: "Minimal monitoring — scheduled task provides reliable persistence",
      risk: "low",
      survivesReboot: true,
      detectionLikelihood: "low",
    });
    recs.push({
      method: "registry_run",
      rationale: "No EDR monitoring — registry Run key is simple and effective",
      risk: "low",
      survivesReboot: true,
      detectionLikelihood: "low",
    });
  }

  return recs;
}
