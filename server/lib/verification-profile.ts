/**
 * Verification Profile System
 * 
 * Defines sector-specific depth settings for Vulnerability Assessment engagements.
 * Controls which verification methods are allowed, scanning windows, and
 * compliance-specific requirements.
 * 
 * The VA pipeline uses these profiles to gate phases:
 *   Recon → Active Discovery → Vuln Detection → Verification → LLM Synthesis
 *   (NO exploitation phase — that's the key difference from Pentest/Red Team)
 */

import type { VerificationStatus, NormalizedFinding } from './finding-normalization.js';

// ─── Verification Profile Interface ────────────────────────────────────────────

export interface VerificationProfile {
  id: string;
  name: string;
  description: string;
  
  // Verification depth limits
  maxVerificationDepth: VerificationStatus;  // Deepest verification allowed
  allowedVerificationMethods: VerificationStatus[];
  
  // Scanning configuration
  scannerConfig: {
    enableNuclei: boolean;
    enableZap: boolean;
    enableBurp: boolean;
    enableTrivy: boolean;
    enableOpenVas: boolean;
    enableNikto: boolean;
    nucleiTemplateCategories?: string[];  // e.g., ['cves', 'misconfigurations', 'exposures']
    zapScanPolicy?: 'light' | 'standard' | 'full';
    burpScanType?: 'passive' | 'active' | 'full';
  };
  
  // Timing constraints
  timing: {
    scanWindowOnly: boolean;        // Only scan during authorized windows
    businessHoursOnly: boolean;     // Restrict to business hours
    maxScanDurationMinutes: number; // Hard cap on scan duration
    cooldownBetweenScansMinutes: number;
  };
  
  // Compliance-specific settings
  compliance?: {
    frameworks: string[];           // Required frameworks for this profile
    requireEvidencePackage: boolean;
    requireRemediationGuidance: boolean;
    requireRiskAcceptanceWorkflow: boolean;
    asvMode?: boolean;              // PCI ASV scanning mode
    continuousMonitoring?: boolean; // FedRAMP ConMon mode
  };
  
  // Sector-specific depth
  sectorDepth: {
    sector: string;
    specialRequirements: string[];
    additionalChecks: string[];
  };
}

// ─── Built-in Verification Profiles ────────────────────────────────────────────

export const VERIFICATION_PROFILES: Record<string, VerificationProfile> = {
  'standard-va': {
    id: 'standard-va',
    name: 'Standard Vulnerability Assessment',
    description: 'General-purpose VA with version matching and configuration checks. No exploitation.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: false,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures', 'default-logins'],
      zapScanPolicy: 'standard',
    },
    timing: {
      scanWindowOnly: false,
      businessHoursOnly: false,
      maxScanDurationMinutes: 240,
      cooldownBetweenScansMinutes: 30,
    },
    sectorDepth: {
      sector: 'general',
      specialRequirements: [],
      additionalChecks: [],
    },
  },
  
  'compliance-pci-asv': {
    id: 'compliance-pci-asv',
    name: 'PCI DSS ASV Scan',
    description: 'PCI DSS Approved Scanning Vendor (ASV) compliant external vulnerability scan. Quarterly requirement.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: true,
      enableTrivy: false,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures', 'default-logins', 'network'],
      zapScanPolicy: 'full',
      burpScanType: 'active',
    },
    timing: {
      scanWindowOnly: true,
      businessHoursOnly: true,
      maxScanDurationMinutes: 480,
      cooldownBetweenScansMinutes: 60,
    },
    compliance: {
      frameworks: ['pci-dss-v4'],
      requireEvidencePackage: true,
      requireRemediationGuidance: true,
      requireRiskAcceptanceWorkflow: true,
      asvMode: true,
    },
    sectorDepth: {
      sector: 'financial',
      specialRequirements: [
        'All external-facing IPs must be scanned',
        'CVSS 4.0+ findings must be remediated or have risk acceptance',
        'Scan must complete within quarterly window',
      ],
      additionalChecks: [
        'SSL/TLS configuration (PCI Req 4.1)',
        'Default credentials (PCI Req 2.1)',
        'Patch management verification (PCI Req 6.3)',
      ],
    },
  },
  
  'compliance-fedramp-conmon': {
    id: 'compliance-fedramp-conmon',
    name: 'FedRAMP Continuous Monitoring',
    description: 'FedRAMP ConMon vulnerability scanning per NIST 800-53 RA-5. Monthly cadence.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: true,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures', 'default-logins', 'network'],
      zapScanPolicy: 'full',
      burpScanType: 'full',
    },
    timing: {
      scanWindowOnly: true,
      businessHoursOnly: false,
      maxScanDurationMinutes: 720,
      cooldownBetweenScansMinutes: 120,
    },
    compliance: {
      frameworks: ['nist-800-53'],
      requireEvidencePackage: true,
      requireRemediationGuidance: true,
      requireRiskAcceptanceWorkflow: true,
      continuousMonitoring: true,
    },
    sectorDepth: {
      sector: 'government',
      specialRequirements: [
        'All system components in authorization boundary must be scanned',
        'Critical/High findings: 30-day remediation deadline',
        'Medium findings: 90-day remediation deadline',
        'Low findings: 180-day remediation deadline',
        'Monthly POA&M updates required',
      ],
      additionalChecks: [
        'FIPS 140-2/3 cryptographic validation',
        'STIG compliance checks',
        'Configuration baseline comparison',
      ],
    },
  },
  
  'compliance-hipaa': {
    id: 'compliance-hipaa',
    name: 'HIPAA Security Assessment',
    description: 'HIPAA Security Rule technical safeguard assessment for systems handling PHI.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: true,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures', 'default-logins'],
      zapScanPolicy: 'standard',
      burpScanType: 'active',
    },
    timing: {
      scanWindowOnly: true,
      businessHoursOnly: false,
      maxScanDurationMinutes: 360,
      cooldownBetweenScansMinutes: 60,
    },
    compliance: {
      frameworks: ['hipaa'],
      requireEvidencePackage: true,
      requireRemediationGuidance: true,
      requireRiskAcceptanceWorkflow: true,
    },
    sectorDepth: {
      sector: 'healthcare',
      specialRequirements: [
        'All systems handling PHI must be in scope',
        'Access control verification (§164.312(a))',
        'Audit controls verification (§164.312(b))',
        'Integrity controls verification (§164.312(c))',
        'Transmission security verification (§164.312(e))',
      ],
      additionalChecks: [
        'PHI data exposure checks',
        'Authentication mechanism assessment',
        'Encryption at rest and in transit verification',
        'Audit logging completeness',
      ],
    },
  },
  
  'compliance-soc2': {
    id: 'compliance-soc2',
    name: 'SOC 2 Technical Assessment',
    description: 'SOC 2 Trust Services Criteria technical vulnerability assessment.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: false,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures'],
      zapScanPolicy: 'standard',
    },
    timing: {
      scanWindowOnly: false,
      businessHoursOnly: false,
      maxScanDurationMinutes: 360,
      cooldownBetweenScansMinutes: 30,
    },
    compliance: {
      frameworks: ['soc2'],
      requireEvidencePackage: true,
      requireRemediationGuidance: true,
      requireRiskAcceptanceWorkflow: false,
    },
    sectorDepth: {
      sector: 'technology',
      specialRequirements: [
        'All in-scope system components must be assessed',
        'Logical access controls verification',
        'Change management process assessment',
      ],
      additionalChecks: [
        'CC6.1 - Logical access security',
        'CC6.6 - Security measures against external threats',
        'CC7.1 - Monitoring of infrastructure and software',
        'CC8.1 - Change management controls',
      ],
    },
  },
  
  'deep-assessment': {
    id: 'deep-assessment',
    name: 'Deep Targeted Assessment',
    description: 'Thorough assessment with all scanners enabled and behavioral verification. For critical systems.',
    maxVerificationDepth: 'behavior_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified', 'behavior_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: true,
      enableBurp: true,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: true,
      nucleiTemplateCategories: ['cves', 'misconfigurations', 'exposures', 'default-logins', 'network', 'technologies'],
      zapScanPolicy: 'full',
      burpScanType: 'full',
    },
    timing: {
      scanWindowOnly: true,
      businessHoursOnly: false,
      maxScanDurationMinutes: 720,
      cooldownBetweenScansMinutes: 60,
    },
    sectorDepth: {
      sector: 'general',
      specialRequirements: [
        'All discovered assets must be scanned',
        'Manual verification of critical findings recommended',
      ],
      additionalChecks: [
        'Full web application scanning',
        'API endpoint discovery and testing',
        'Container image scanning',
        'Dependency vulnerability analysis',
      ],
    },
  },
  
  'continuous-monitoring': {
    id: 'continuous-monitoring',
    name: 'Continuous Monitoring (Lightweight)',
    description: 'Lightweight recurring scan for ongoing vulnerability monitoring. Version/config checks only.',
    maxVerificationDepth: 'configuration_verified',
    allowedVerificationMethods: ['unverified', 'configuration_verified'],
    scannerConfig: {
      enableNuclei: true,
      enableZap: false,
      enableBurp: false,
      enableTrivy: true,
      enableOpenVas: false,
      enableNikto: false,
      nucleiTemplateCategories: ['cves', 'misconfigurations'],
    },
    timing: {
      scanWindowOnly: false,
      businessHoursOnly: false,
      maxScanDurationMinutes: 60,
      cooldownBetweenScansMinutes: 15,
    },
    sectorDepth: {
      sector: 'general',
      specialRequirements: [],
      additionalChecks: [],
    },
  },
};

// ─── VA Pipeline Phase Definitions ─────────────────────────────────────────────

export type VAPipelinePhase =
  | 'asset_discovery'        // Passive + active recon to discover all assets
  | 'port_service_enum'      // Port scanning and service fingerprinting
  | 'vuln_detection'         // Multi-scanner vulnerability detection
  | 'verification'           // Verification of findings (up to profile max depth)
  | 'risk_scoring'           // CVSS + EPSS + business context scoring
  | 'llm_synthesis'          // LLM-powered analysis, prioritization, remediation
  | 'reporting';             // Report generation with compliance mapping

export interface VAPipelineConfig {
  engagementId: number;
  profile: VerificationProfile;
  targets: string[];                    // Domain names, IPs, CIDRs
  selectedFrameworks: string[];         // Compliance frameworks to map against
  
  // Phase gating
  phases: VAPipelinePhase[];            // Ordered phases to execute
  skipPhases?: VAPipelinePhase[];       // Phases to skip (e.g., skip verification for quick scan)
  
  // Options
  maxFindingsForLlmSynthesis: number;   // Cap on findings sent to LLM
  includeRemediationGuidance: boolean;
  includeComplianceMapping: boolean;
  generateExecutiveSummary: boolean;
}

/**
 * Build the default VA pipeline config from a verification profile.
 * The key difference from pentest: NO exploitation phases.
 */
export function buildVAPipelineConfig(params: {
  engagementId: number;
  profileId: string;
  targets: string[];
  selectedFrameworks?: string[];
}): VAPipelineConfig {
  const profile = VERIFICATION_PROFILES[params.profileId] || VERIFICATION_PROFILES['standard-va'];
  
  // VA always runs these phases in order — NO exploitation
  const phases: VAPipelinePhase[] = [
    'asset_discovery',
    'port_service_enum',
    'vuln_detection',
    'verification',
    'risk_scoring',
    'llm_synthesis',
    'reporting',
  ];
  
  // For continuous monitoring, skip verification and LLM synthesis
  const skipPhases: VAPipelinePhase[] = [];
  if (params.profileId === 'continuous-monitoring') {
    skipPhases.push('verification', 'llm_synthesis');
  }
  
  const frameworks = params.selectedFrameworks || profile.compliance?.frameworks || [];
  
  return {
    engagementId: params.engagementId,
    profile,
    targets: params.targets,
    selectedFrameworks: frameworks,
    phases,
    skipPhases,
    maxFindingsForLlmSynthesis: 100,
    includeRemediationGuidance: profile.compliance?.requireRemediationGuidance ?? true,
    includeComplianceMapping: frameworks.length > 0,
    generateExecutiveSummary: true,
  };
}

// ─── VA Phase Gating ───────────────────────────────────────────────────────────

/**
 * Check if a verification status is allowed by the profile.
 * VA engagements NEVER allow exploit_safe or exploit_full.
 */
export function isVerificationAllowed(
  status: VerificationStatus,
  profile: VerificationProfile
): boolean {
  return profile.allowedVerificationMethods.includes(status);
}

/**
 * Get the maximum verification depth for a finding based on the profile.
 * Returns the deepest allowed verification that hasn't been reached yet.
 */
export function getNextVerificationStep(
  currentStatus: VerificationStatus,
  profile: VerificationProfile
): VerificationStatus | null {
  const order: VerificationStatus[] = [
    'unverified',
    'configuration_verified',
    'behavior_verified',
    'exploit_safe',
    'exploit_full',
  ];
  
  const currentIdx = order.indexOf(currentStatus);
  const maxIdx = order.indexOf(profile.maxVerificationDepth);
  
  if (currentIdx >= maxIdx) return null; // Already at max depth
  
  // Find next allowed step
  for (let i = currentIdx + 1; i <= maxIdx; i++) {
    if (profile.allowedVerificationMethods.includes(order[i])) {
      return order[i];
    }
  }
  
  return null;
}

/**
 * Check if a VA pipeline phase should be executed based on config.
 */
export function shouldExecutePhase(
  phase: VAPipelinePhase,
  config: VAPipelineConfig
): boolean {
  if (!config.phases.includes(phase)) return false;
  if (config.skipPhases?.includes(phase)) return false;
  return true;
}

// ─── VA Finding Prioritization ─────────────────────────────────────────────────

export interface PrioritizedFinding extends NormalizedFinding {
  priorityScore: number;        // 0-100 composite score
  priorityRank: number;         // 1-based rank
  priorityFactors: {
    severityWeight: number;     // 0-30
    exploitabilityWeight: number; // 0-25
    corroborationWeight: number;  // 0-20
    complianceWeight: number;     // 0-15
    assetCriticalityWeight: number; // 0-10
  };
  remediationDeadline?: string; // ISO date based on compliance requirements
}

/**
 * Prioritize findings using a weighted scoring model.
 * This is the VA-specific prioritization that considers compliance deadlines,
 * exploitability, and corroboration — not just CVSS score.
 */
export function prioritizeFindings(
  findings: NormalizedFinding[],
  profile: VerificationProfile
): PrioritizedFinding[] {
  const scored = findings.map(f => {
    // Severity weight (0-30)
    const severityMap: Record<string, number> = {
      critical: 30, high: 22, medium: 14, low: 6, info: 0,
    };
    const severityWeight = severityMap[f.severity] || 0;
    
    // Exploitability weight (0-25)
    let exploitabilityWeight = 0;
    if (f.exploitability.isKev) exploitabilityWeight += 10;
    if (f.exploitability.hasPublicExploit) exploitabilityWeight += 5;
    if (f.exploitability.hasMetasploitModule) exploitabilityWeight += 5;
    if (f.exploitability.hasNucleiTemplate) exploitabilityWeight += 3;
    if (f.exploitability.epssScore && f.exploitability.epssScore > 0.5) exploitabilityWeight += 2;
    exploitabilityWeight = Math.min(25, exploitabilityWeight);
    
    // Corroboration weight (0-20)
    const corroborationMap: Record<string, number> = {
      confirmed: 20, probable: 12, potential: 5,
    };
    const corroborationWeight = corroborationMap[f.corroborationTier] || 0;
    
    // Compliance weight (0-15)
    let complianceWeight = 0;
    if (f.complianceMappings?.length) {
      const directViolations = f.complianceMappings.filter(m => m.gapType === 'direct_violation').length;
      complianceWeight = Math.min(15, directViolations * 5 + (f.complianceMappings.length - directViolations) * 2);
    }
    
    // Asset criticality weight (0-10) — placeholder, would be enriched by business context
    const assetCriticalityWeight = 5; // Default medium criticality
    
    const priorityScore = severityWeight + exploitabilityWeight + corroborationWeight + complianceWeight + assetCriticalityWeight;
    
    // Remediation deadline based on compliance profile
    let remediationDeadline: string | undefined;
    if (profile.compliance) {
      const now = new Date();
      if (f.severity === 'critical' || f.severity === 'high') {
        now.setDate(now.getDate() + 30);
      } else if (f.severity === 'medium') {
        now.setDate(now.getDate() + 90);
      } else {
        now.setDate(now.getDate() + 180);
      }
      remediationDeadline = now.toISOString().split('T')[0];
    }
    
    return {
      ...f,
      priorityScore,
      priorityRank: 0, // Set after sorting
      priorityFactors: {
        severityWeight,
        exploitabilityWeight,
        corroborationWeight,
        complianceWeight,
        assetCriticalityWeight,
      },
      remediationDeadline,
    };
  });
  
  // Sort by priority score descending
  scored.sort((a, b) => b.priorityScore - a.priorityScore);
  
  // Assign ranks
  scored.forEach((f, i) => { f.priorityRank = i + 1; });
  
  return scored;
}

// ─── VA Report Data Structure ──────────────────────────────────────────────────

export interface VAReportData {
  engagementId: number;
  profileUsed: string;
  scanTimestamp: number;
  
  // Executive summary
  executiveSummary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byVerification: Record<string, number>;
    topRisks: Array<{ title: string; severity: string; priorityScore: number }>;
    complianceGaps: Array<{ framework: string; controlId: string; findingCount: number }>;
  };
  
  // Findings inventory
  findings: PrioritizedFinding[];
  
  // Scanner coverage
  scannerCoverage: {
    scannersUsed: string[];
    totalTargets: number;
    totalAssetsDiscovered: number;
    scanDurationMinutes: number;
  };
  
  // Compliance mapping
  complianceSummary?: {
    frameworks: string[];
    controlsAffected: number;
    directViolations: number;
    contributingWeaknesses: number;
    gapsByFramework: Record<string, Array<{
      controlId: string;
      controlTitle: string;
      findingCount: number;
      highestSeverity: string;
    }>>;
  };
  
  // Remediation roadmap
  remediationRoadmap: {
    immediate: PrioritizedFinding[];    // Priority 1-2
    shortTerm: PrioritizedFinding[];    // Priority 3
    mediumTerm: PrioritizedFinding[];   // Priority 4
    longTerm: PrioritizedFinding[];     // Priority 5+
  };
}

/**
 * Build VA report data from prioritized findings.
 */
export function buildVAReportData(params: {
  engagementId: number;
  profileId: string;
  findings: PrioritizedFinding[];
  scannerCoverage: VAReportData['scannerCoverage'];
  selectedFrameworks: string[];
}): VAReportData {
  const { findings } = params;
  
  // Executive summary
  const bySeverity: Record<string, number> = {};
  const byVerification: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byVerification[f.verificationStatus] = (byVerification[f.verificationStatus] || 0) + 1;
  }
  
  const topRisks = findings.slice(0, 10).map(f => ({
    title: f.title,
    severity: f.severity,
    priorityScore: f.priorityScore,
  }));
  
  // Compliance gaps
  const complianceGapMap = new Map<string, { framework: string; controlId: string; findingCount: number }>();
  for (const f of findings) {
    for (const m of f.complianceMappings || []) {
      const key = `${m.framework}:${m.controlId}`;
      const existing = complianceGapMap.get(key);
      if (existing) {
        existing.findingCount++;
      } else {
        complianceGapMap.set(key, { framework: m.framework, controlId: m.controlId, findingCount: 1 });
      }
    }
  }
  
  // Compliance summary by framework
  const gapsByFramework: Record<string, Array<{ controlId: string; controlTitle: string; findingCount: number; highestSeverity: string }>> = {};
  for (const f of findings) {
    for (const m of f.complianceMappings || []) {
      if (!gapsByFramework[m.framework]) gapsByFramework[m.framework] = [];
      const existing = gapsByFramework[m.framework].find(g => g.controlId === m.controlId);
      if (existing) {
        existing.findingCount++;
      } else {
        gapsByFramework[m.framework].push({
          controlId: m.controlId,
          controlTitle: m.controlTitle,
          findingCount: 1,
          highestSeverity: f.severity,
        });
      }
    }
  }
  
  // Remediation roadmap
  const remediationRoadmap = {
    immediate: findings.filter(f => f.remediation?.priority === 1 || f.severity === 'critical'),
    shortTerm: findings.filter(f => f.remediation?.priority === 2 || (f.severity === 'high' && f.remediation?.priority !== 1)),
    mediumTerm: findings.filter(f => f.remediation?.priority === 3 || f.severity === 'medium'),
    longTerm: findings.filter(f => (f.remediation?.priority || 5) >= 4 && f.severity !== 'critical' && f.severity !== 'high' && f.severity !== 'medium'),
  };
  
  return {
    engagementId: params.engagementId,
    profileUsed: params.profileId,
    scanTimestamp: Date.now(),
    executiveSummary: {
      totalFindings: findings.length,
      bySeverity,
      byVerification,
      topRisks,
      complianceGaps: Array.from(complianceGapMap.values()),
    },
    findings,
    scannerCoverage: params.scannerCoverage,
    complianceSummary: params.selectedFrameworks.length > 0 ? {
      frameworks: params.selectedFrameworks,
      controlsAffected: complianceGapMap.size,
      directViolations: Array.from(complianceGapMap.values()).filter(g => 
        findings.some(f => f.complianceMappings?.some(m => 
          m.controlId === g.controlId && m.gapType === 'direct_violation'
        ))
      ).length,
      contributingWeaknesses: complianceGapMap.size - Array.from(complianceGapMap.values()).filter(g =>
        findings.some(f => f.complianceMappings?.some(m =>
          m.controlId === g.controlId && m.gapType === 'direct_violation'
        ))
      ).length,
      gapsByFramework,
    } : undefined,
    remediationRoadmap,
  };
}

// ─── Exports ───────────────────────────────────────────────────────────────────

export function getVerificationProfile(profileId: string): VerificationProfile | undefined {
  return VERIFICATION_PROFILES[profileId];
}

export function listVerificationProfiles(): Array<{ id: string; name: string; description: string }> {
  return Object.values(VERIFICATION_PROFILES).map(p => ({
    id: p.id,
    name: p.name,
    description: p.description,
  }));
}
