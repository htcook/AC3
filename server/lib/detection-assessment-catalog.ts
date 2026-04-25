/**
 * Detection Assessment Catalog
 * 
 * Reframes the EDR evasion catalog as a detection-test knowledge base.
 * Instead of "Technique X bypasses CrowdStrike Falcon," this module frames entries as
 * "Technique X exercises detection capability Y, implemented in CrowdStrike Falcon."
 * 
 * Adds:
 * - Expected indicators (what a good detection SHOULD produce)
 * - Public source citations
 * - Vendor purple team policies
 * - Detection capability mapping
 */

import {
  EDR_EVASION_CATALOG,
  type EvasionTechniqueEntry,
  getEvasionTechniquesForProduct,
  crossReferenceEvasionStrategy,
} from "./edr-evasion-catalog";

// ─── Detection Assessment Entry (extends EvasionTechniqueEntry) ────────────

export interface DetectionAssessmentEntry {
  /** Original evasion technique entry */
  technique: EvasionTechniqueEntry;
  /** Detection-centric reframing */
  detectionFraming: {
    /** What detection capability this technique exercises */
    capabilityTested: string;
    /** Detection-centric description (not evasion-centric) */
    detectionDescription: string;
    /** Expected indicators that a competent detection should produce */
    expectedIndicators: string[];
    /** Expected telemetry sources (process events, network logs, etc.) */
    expectedTelemetrySources: string[];
    /** Minimum detection maturity level required */
    minimumDetectionMaturity: "basic" | "intermediate" | "advanced" | "expert";
  };
  /** Public references for this technique */
  publicReferences: PublicReference[];
  /** Vendor-specific detection information */
  vendorDetectionInfo: VendorDetectionInfo[];
}

export interface PublicReference {
  /** Reference title */
  title: string;
  /** URL */
  url: string;
  /** Source type */
  type: "mitre_attack" | "blog" | "paper" | "vendor_advisory" | "cve" | "github";
  /** Date published */
  publishedDate?: string;
}

export interface VendorDetectionInfo {
  /** Vendor/product name */
  vendor: string;
  /** Product name */
  product: string;
  /** Does this vendor have a documented purple team policy? */
  purpleTeamPolicyExists: boolean;
  /** Purple team policy summary */
  purpleTeamPolicySummary?: string;
  /** Purple team policy URL */
  purpleTeamPolicyUrl?: string;
  /** Known detection rule name for this technique */
  detectionRuleName?: string;
  /** Detection confidence */
  detectionConfidence: "high" | "medium" | "low" | "unknown";
}

// ─── Vendor Purple Team Policies ───────────────────────────────────────────

export const VENDOR_PURPLE_TEAM_POLICIES: Record<string, {
  vendor: string;
  product: string;
  policyExists: boolean;
  policySummary: string;
  policyUrl: string;
  mdrNotificationRequired: boolean;
  testingGuidelines: string;
}> = {
  "crowdstrike_falcon": {
    vendor: "CrowdStrike",
    product: "Falcon",
    policyExists: true,
    policySummary: "CrowdStrike supports authorized penetration testing and purple team exercises. Customers must notify CrowdStrike Falcon Complete/OverWatch before testing to prevent false incident response. Testing should be scoped and documented.",
    policyUrl: "https://www.crowdstrike.com/resources/",
    mdrNotificationRequired: true,
    testingGuidelines: "Notify Falcon Complete 48hrs in advance. Provide IP ranges, timeframes, and technique list. CrowdStrike will suppress automated response for the testing window.",
  },
  "microsoft_defender": {
    vendor: "Microsoft",
    product: "Defender for Endpoint",
    policyExists: true,
    policySummary: "Microsoft supports authorized security testing. Customers should configure exclusions or notify Microsoft Defender Experts before purple team exercises. Attack simulation training is available natively.",
    policyUrl: "https://learn.microsoft.com/en-us/microsoft-365/security/",
    mdrNotificationRequired: true,
    testingGuidelines: "Use Attack Simulation Training for phishing tests. For endpoint testing, configure temporary exclusions or notify Defender Experts. Document all testing in Azure Sentinel.",
  },
  "sentinelone": {
    vendor: "SentinelOne",
    product: "Singularity",
    policyExists: true,
    policySummary: "SentinelOne supports purple team exercises. Vigilance MDR customers must notify the SOC before testing. Temporary policy modifications can be made for testing windows.",
    policyUrl: "https://www.sentinelone.com/resources/",
    mdrNotificationRequired: true,
    testingGuidelines: "Notify Vigilance SOC 24hrs in advance. Provide scope and technique list. Consider using Detect-only policy during testing to observe without blocking.",
  },
  "carbon_black": {
    vendor: "VMware",
    product: "Carbon Black",
    policyExists: true,
    policySummary: "Carbon Black supports authorized security testing. MDR customers should coordinate with the CB ThreatSight team before exercises.",
    policyUrl: "https://www.vmware.com/security/",
    mdrNotificationRequired: true,
    testingGuidelines: "Coordinate with ThreatSight team. Consider sensor bypass rules for testing hosts during exercise window.",
  },
  "palo_alto_cortex": {
    vendor: "Palo Alto Networks",
    product: "Cortex XDR",
    policyExists: true,
    policySummary: "Palo Alto supports authorized testing. Unit 42 MDR customers must coordinate before purple team exercises.",
    policyUrl: "https://www.paloaltonetworks.com/cortex/",
    mdrNotificationRequired: true,
    testingGuidelines: "Notify Unit 42 MDR. Use Cortex XDR's built-in simulation capabilities where possible. Document all testing in XSOAR.",
  },
  "elastic_security": {
    vendor: "Elastic",
    product: "Elastic Security",
    policyExists: true,
    policySummary: "Elastic Security is open-source and supports purple team exercises. Detection rules are publicly documented and can be tested against.",
    policyUrl: "https://www.elastic.co/security-labs/",
    mdrNotificationRequired: false,
    testingGuidelines: "Review Elastic detection rules repository. Use Elastic's prebuilt rules as detection baselines. All rules are open-source and testable.",
  },
  "trellix": {
    vendor: "Trellix",
    product: "Trellix XDR",
    policyExists: true,
    policySummary: "Trellix supports authorized security testing and provides purple team engagement support through their professional services.",
    policyUrl: "https://www.trellix.com/",
    mdrNotificationRequired: true,
    testingGuidelines: "Coordinate with Trellix MDR. Use ePO to configure test policies during exercise windows.",
  },
  "sophos": {
    vendor: "Sophos",
    product: "Intercept X",
    policyExists: true,
    policySummary: "Sophos supports authorized testing. MTR customers must notify the SOC before exercises.",
    policyUrl: "https://www.sophos.com/",
    mdrNotificationRequired: true,
    testingGuidelines: "Notify Sophos MTR team. Consider tamper protection adjustments for testing hosts.",
  },
};

// ─── Detection Capability Mapping ──────────────────────────────────────────

const TECHNIQUE_DETECTION_CAPABILITIES: Record<string, {
  capability: string;
  description: string;
  expectedIndicators: string[];
  expectedTelemetry: string[];
  maturityLevel: "basic" | "intermediate" | "advanced" | "expert";
}> = {
  // Memory techniques
  "memory": {
    capability: "In-Memory Threat Detection",
    description: "Exercises the defensive stack's ability to detect in-memory threats including process injection, reflective loading, and memory-resident malware.",
    expectedIndicators: [
      "Process injection alert (cross-process memory write)",
      "Suspicious memory allocation (RWX pages)",
      "Anomalous thread creation in legitimate process",
      "ETW provider detection of memory manipulation",
    ],
    expectedTelemetry: ["process_events", "memory_events", "etw_logs", "kernel_callbacks"],
    maturityLevel: "advanced",
  },
  "process": {
    capability: "Process Behavior Analysis",
    description: "Exercises the defensive stack's ability to detect anomalous process behavior including parent-child relationship violations, suspicious command lines, and process hollowing.",
    expectedIndicators: [
      "Suspicious parent-child process relationship",
      "Known-bad command line pattern",
      "Process hollowing detection (unmapped code execution)",
      "Suspicious process creation chain",
    ],
    expectedTelemetry: ["process_events", "command_line_logging", "sysmon_events"],
    maturityLevel: "intermediate",
  },
  "network": {
    capability: "Network Threat Detection",
    description: "Exercises the defensive stack's ability to detect malicious network activity including C2 communications, lateral movement, and data exfiltration.",
    expectedIndicators: [
      "Suspicious outbound connection to unknown domain",
      "Beaconing pattern detection",
      "DNS tunneling alert",
      "Lateral movement via SMB/WMI/WinRM",
    ],
    expectedTelemetry: ["network_flows", "dns_logs", "proxy_logs", "firewall_logs"],
    maturityLevel: "intermediate",
  },
  "credential": {
    capability: "Credential Theft Detection",
    description: "Exercises the defensive stack's ability to detect credential harvesting including LSASS access, Kerberos attacks, and credential dumping.",
    expectedIndicators: [
      "LSASS memory access by non-system process",
      "Kerberoasting activity (TGS requests for service accounts)",
      "DCSync replication request from non-DC",
      "Suspicious SAM database access",
    ],
    expectedTelemetry: ["process_events", "security_event_log", "kerberos_logs", "etw_logs"],
    maturityLevel: "intermediate",
  },
  "persistence": {
    capability: "Persistence Mechanism Detection",
    description: "Exercises the defensive stack's ability to detect persistence establishment including registry modifications, scheduled tasks, and service creation.",
    expectedIndicators: [
      "Registry Run key modification",
      "New scheduled task creation",
      "New service installation",
      "WMI event subscription creation",
      "Startup folder modification",
    ],
    expectedTelemetry: ["registry_events", "scheduled_task_logs", "service_events", "wmi_events"],
    maturityLevel: "basic",
  },
  "discovery": {
    capability: "Reconnaissance Detection",
    description: "Exercises the defensive stack's ability to detect internal reconnaissance including network scanning, AD enumeration, and system discovery.",
    expectedIndicators: [
      "Internal port scanning activity",
      "AD enumeration (LDAP queries for privileged groups)",
      "Suspicious use of built-in discovery commands",
      "BloodHound/SharpHound collection activity",
    ],
    expectedTelemetry: ["network_flows", "ldap_logs", "command_line_logging", "process_events"],
    maturityLevel: "basic",
  },
  "lateral": {
    capability: "Lateral Movement Detection",
    description: "Exercises the defensive stack's ability to detect lateral movement including pass-the-hash, remote service exploitation, and RDP pivoting.",
    expectedIndicators: [
      "Pass-the-hash authentication pattern",
      "Remote service creation on target host",
      "RDP connection from unexpected source",
      "WMI/PSRemoting from non-admin workstation",
    ],
    expectedTelemetry: ["authentication_logs", "network_flows", "rdp_logs", "wmi_events"],
    maturityLevel: "intermediate",
  },
  "collection": {
    capability: "Data Collection Detection",
    description: "Exercises the defensive stack's ability to detect data staging and collection including archive creation, clipboard monitoring, and screen capture.",
    expectedIndicators: [
      "Suspicious archive creation (large zip/rar in temp directory)",
      "Bulk file access across multiple directories",
      "Screen capture utility execution",
      "Email collection activity",
    ],
    expectedTelemetry: ["file_events", "process_events", "email_logs"],
    maturityLevel: "advanced",
  },
  "exfiltration": {
    capability: "Data Exfiltration Detection",
    description: "Exercises the defensive stack's ability to detect data exfiltration including DNS tunneling, HTTP(S) exfil, and cloud storage uploads.",
    expectedIndicators: [
      "Large outbound data transfer to unknown destination",
      "DNS tunneling pattern (high-entropy subdomain queries)",
      "Unauthorized cloud storage upload",
      "Encrypted channel to non-standard port",
    ],
    expectedTelemetry: ["network_flows", "dns_logs", "proxy_logs", "dlp_events"],
    maturityLevel: "advanced",
  },
};

// ─── Core Functions ────────────────────────────────────────────────────────

/**
 * Reframe an evasion technique entry as a detection assessment entry.
 * Changes the framing from "bypasses X" to "exercises detection capability Y."
 */
export function reframeAsDetectionAssessment(technique: EvasionTechniqueEntry): DetectionAssessmentEntry {
  const capabilityInfo = TECHNIQUE_DETECTION_CAPABILITIES[technique.category] || {
    capability: `${technique.category} Detection`,
    description: `Exercises the defensive stack's ${technique.category} detection capabilities.`,
    expectedIndicators: [`Alert for ${technique.name}`],
    expectedTelemetry: ["process_events"],
    maturityLevel: "intermediate" as const,
  };

  // Build vendor detection info
  const vendorDetectionInfo: VendorDetectionInfo[] = technique.bypassesProducts.map(product => {
    const normalizedKey = product.toLowerCase().replace(/\s+/g, "_");
    const vendorPolicy = Object.values(VENDOR_PURPLE_TEAM_POLICIES).find(
      v => v.product.toLowerCase() === product.toLowerCase() ||
           normalizedKey.includes(v.vendor.toLowerCase())
    );

    return {
      vendor: vendorPolicy?.vendor || product.split(" ")[0],
      product,
      purpleTeamPolicyExists: !!vendorPolicy?.policyExists,
      purpleTeamPolicySummary: vendorPolicy?.policySummary,
      purpleTeamPolicyUrl: vendorPolicy?.policyUrl,
      detectionConfidence: technique.reliability === "patched" ? "high" as const :
                           technique.detectionRisk === "high" ? "high" as const :
                           technique.detectionRisk === "medium" ? "medium" as const : "low" as const,
    };
  });

  // Build public references
  const publicReferences: PublicReference[] = technique.mitreIds.map(id => ({
    title: `MITRE ATT&CK: ${id}`,
    url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
    type: "mitre_attack" as const,
  }));

  return {
    technique,
    detectionFraming: {
      capabilityTested: capabilityInfo.capability,
      detectionDescription: `${technique.name} exercises ${capabilityInfo.capability.toLowerCase()}. ${capabilityInfo.description}`,
      expectedIndicators: capabilityInfo.expectedIndicators,
      expectedTelemetrySources: capabilityInfo.expectedTelemetry,
      minimumDetectionMaturity: capabilityInfo.maturityLevel,
    },
    publicReferences,
    vendorDetectionInfo,
  };
}

/**
 * Get the full detection assessment catalog — all evasion techniques reframed as detection tests.
 */
export function getDetectionAssessmentCatalog(): DetectionAssessmentEntry[] {
  return EDR_EVASION_CATALOG.map(reframeAsDetectionAssessment);
}

/**
 * Get detection assessments for a specific product.
 * Returns techniques that exercise detection capabilities of the given product.
 */
export function getDetectionAssessmentsForProduct(productName: string): DetectionAssessmentEntry[] {
  return getEvasionTechniquesForProduct(productName).map(reframeAsDetectionAssessment);
}

/**
 * Get the vendor purple team policy for a product.
 */
export function getVendorPurpleTeamPolicy(productName: string): typeof VENDOR_PURPLE_TEAM_POLICIES[string] | undefined {
  const normalizedKey = productName.toLowerCase().replace(/\s+/g, "_");
  return Object.values(VENDOR_PURPLE_TEAM_POLICIES).find(
    v => v.product.toLowerCase() === productName.toLowerCase() ||
         normalizedKey.includes(v.vendor.toLowerCase())
  );
}

/**
 * Cross-reference detection assessment for a defensive stack.
 * Returns a detection-centric view of what capabilities can be tested.
 */
export function crossReferenceDetectionAssessment(detectedProducts: string[]): {
  totalAssessments: number;
  byCapability: Record<string, { count: number; maturityLevel: string; assessments: DetectionAssessmentEntry[] }>;
  byProduct: Record<string, { count: number; vendorPolicy: boolean }>;
  vendorPolicies: Array<typeof VENDOR_PURPLE_TEAM_POLICIES[string]>;
} {
  const xref = crossReferenceEvasionStrategy(detectedProducts);
  const assessments = xref.techniques.map(t => reframeAsDetectionAssessment(t));

  const byCapability: Record<string, { count: number; maturityLevel: string; assessments: DetectionAssessmentEntry[] }> = {};
  const byProduct: Record<string, { count: number; vendorPolicy: boolean }> = {};

  for (const a of assessments) {
    const cap = a.detectionFraming.capabilityTested;
    if (!byCapability[cap]) {
      byCapability[cap] = { count: 0, maturityLevel: a.detectionFraming.minimumDetectionMaturity, assessments: [] };
    }
    byCapability[cap].count++;
    byCapability[cap].assessments.push(a);

    for (const v of a.vendorDetectionInfo) {
      if (!byProduct[v.product]) {
        byProduct[v.product] = { count: 0, vendorPolicy: v.purpleTeamPolicyExists };
      }
      byProduct[v.product].count++;
    }
  }

  const vendorPolicies = detectedProducts
    .map(p => getVendorPurpleTeamPolicy(p))
    .filter((p): p is typeof VENDOR_PURPLE_TEAM_POLICIES[string] => p !== undefined);

  return {
    totalAssessments: assessments.length,
    byCapability,
    byProduct,
    vendorPolicies,
  };
}

/**
 * Get a detection-centric summary suitable for LLM context injection.
 * Reframes the evasion catalog summary as a detection assessment summary.
 */
export function getDetectionAssessmentSummaryForLLM(detectedProducts: string[]): string {
  const xref = crossReferenceDetectionAssessment(detectedProducts);
  const lines = [
    `## Detection Assessment Cross-Reference (${detectedProducts.length} products in defensive stack)`,
    `Total detection tests available: ${xref.totalAssessments}`,
    "",
    "### Detection Capabilities to Test:",
  ];

  for (const [cap, info] of Object.entries(xref.byCapability)) {
    lines.push(`\n#### ${cap} (${info.count} tests, ${info.maturityLevel} maturity required)`);
    for (const a of info.assessments.slice(0, 5)) {
      lines.push(`  • ${a.technique.name} [${a.technique.mitreIds.join(",")}]`);
      lines.push(`    Expected indicators: ${a.detectionFraming.expectedIndicators.slice(0, 2).join("; ")}`);
      lines.push(`    Telemetry sources: ${a.detectionFraming.expectedTelemetrySources.join(", ")}`);
    }
  }

  if (xref.vendorPolicies.length > 0) {
    lines.push("\n### Vendor Purple Team Policies:");
    for (const vp of xref.vendorPolicies) {
      lines.push(`  • ${vp.vendor} ${vp.product}: ${vp.policySummary.slice(0, 150)}...`);
      lines.push(`    MDR notification required: ${vp.mdrNotificationRequired ? "Yes" : "No"}`);
    }
  }

  return lines.join("\n");
}
