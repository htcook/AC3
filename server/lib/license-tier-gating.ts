/**
 * License-Tier Gating
 * 
 * Controls which engagement types are available based on the organization's
 * license tier. Enforces both backend creation restrictions and provides
 * UI gating information.
 * 
 * Tier Mapping:
 *   Standard:     VA, Bug Bounty, Phishing, Tabletop
 *   Professional: + Pentest, Purple Team
 *   Enterprise:   + Red Team, C2 integration, advanced post-exploitation
 */

// ─── License Tier Types ────────────────────────────────────────────────────────

export type LicenseTier = 'standard' | 'professional' | 'enterprise';

export type EngagementType = 
  | 'vulnerability_assessment'
  | 'bug_bounty'
  | 'phishing'
  | 'tabletop'
  | 'pentest'
  | 'purple_team'
  | 'red_team';

export interface TierConfig {
  tier: LicenseTier;
  displayName: string;
  description: string;
  allowedEngagementTypes: EngagementType[];
  features: TierFeature[];
  maxConcurrentEngagements: number;
  maxTargetsPerEngagement: number;
  retentionDays: number;
  supportLevel: 'community' | 'standard' | 'priority' | 'dedicated';
}

export interface TierFeature {
  id: string;
  name: string;
  description: string;
  included: boolean;
}

// ─── Tier Configuration ────────────────────────────────────────────────────────

export const TIER_CONFIGS: Record<LicenseTier, TierConfig> = {
  standard: {
    tier: 'standard',
    displayName: 'Standard',
    description: 'Essential vulnerability assessment and bug bounty capabilities for security teams.',
    allowedEngagementTypes: ['vulnerability_assessment', 'bug_bounty', 'phishing', 'tabletop'],
    features: [
      { id: 'va', name: 'Vulnerability Assessment', description: 'Multi-scanner VA with normalization and dedup', included: true },
      { id: 'bug_bounty', name: 'Bug Bounty Research', description: 'Program policy parsing, scope enforcement, submission workflow', included: true },
      { id: 'phishing', name: 'Phishing Campaigns', description: 'GoPhish-integrated phishing simulation', included: true },
      { id: 'tabletop', name: 'Tabletop Exercises', description: 'Scenario-based tabletop exercises', included: true },
      { id: 'compliance', name: 'Compliance Mapping', description: 'NIST, PCI-DSS, HIPAA, SOC 2, ISO 27001 mapping', included: true },
      { id: 'normalization', name: 'Finding Normalization', description: 'Multi-scanner finding dedup and corroboration', included: true },
      { id: 'reporting_basic', name: 'Basic Reporting', description: 'VA and compliance reports', included: true },
      { id: 'pentest', name: 'Penetration Testing', description: 'Full pentest pipeline with exploitation', included: false },
      { id: 'purple_team', name: 'Purple Team', description: 'Detection assessment and bilateral timeline', included: false },
      { id: 'red_team', name: 'Red Team', description: 'Full adversary emulation with C2', included: false },
      { id: 'c2_integration', name: 'C2 Integration', description: 'Caldera/Sliver/Cobalt Strike integration', included: false },
      { id: 'post_exploit', name: 'Post-Exploitation', description: 'Automated post-exploitation pipeline', included: false },
    ],
    maxConcurrentEngagements: 5,
    maxTargetsPerEngagement: 50,
    retentionDays: 90,
    supportLevel: 'standard',
  },
  
  professional: {
    tier: 'professional',
    displayName: 'Professional',
    description: 'Full penetration testing and purple team capabilities for advanced security operations.',
    allowedEngagementTypes: ['vulnerability_assessment', 'bug_bounty', 'phishing', 'tabletop', 'pentest', 'purple_team'],
    features: [
      { id: 'va', name: 'Vulnerability Assessment', description: 'Multi-scanner VA with normalization and dedup', included: true },
      { id: 'bug_bounty', name: 'Bug Bounty Research', description: 'Program policy parsing, scope enforcement, submission workflow', included: true },
      { id: 'phishing', name: 'Phishing Campaigns', description: 'GoPhish-integrated phishing simulation', included: true },
      { id: 'tabletop', name: 'Tabletop Exercises', description: 'Scenario-based tabletop exercises', included: true },
      { id: 'compliance', name: 'Compliance Mapping', description: 'NIST, PCI-DSS, HIPAA, SOC 2, ISO 27001 mapping', included: true },
      { id: 'normalization', name: 'Finding Normalization', description: 'Multi-scanner finding dedup and corroboration', included: true },
      { id: 'reporting_basic', name: 'Basic Reporting', description: 'VA and compliance reports', included: true },
      { id: 'pentest', name: 'Penetration Testing', description: 'Full pentest pipeline with exploitation', included: true },
      { id: 'purple_team', name: 'Purple Team', description: 'Detection assessment and bilateral timeline', included: true },
      { id: 'red_team', name: 'Red Team', description: 'Full adversary emulation with C2', included: false },
      { id: 'c2_integration', name: 'C2 Integration', description: 'Caldera/Sliver/Cobalt Strike integration', included: false },
      { id: 'post_exploit', name: 'Post-Exploitation', description: 'Automated post-exploitation pipeline', included: false },
    ],
    maxConcurrentEngagements: 20,
    maxTargetsPerEngagement: 200,
    retentionDays: 365,
    supportLevel: 'priority',
  },
  
  enterprise: {
    tier: 'enterprise',
    displayName: 'Enterprise',
    description: 'Full adversary emulation, red team operations, and C2 integration for elite security teams.',
    allowedEngagementTypes: ['vulnerability_assessment', 'bug_bounty', 'phishing', 'tabletop', 'pentest', 'purple_team', 'red_team'],
    features: [
      { id: 'va', name: 'Vulnerability Assessment', description: 'Multi-scanner VA with normalization and dedup', included: true },
      { id: 'bug_bounty', name: 'Bug Bounty Research', description: 'Program policy parsing, scope enforcement, submission workflow', included: true },
      { id: 'phishing', name: 'Phishing Campaigns', description: 'GoPhish-integrated phishing simulation', included: true },
      { id: 'tabletop', name: 'Tabletop Exercises', description: 'Scenario-based tabletop exercises', included: true },
      { id: 'compliance', name: 'Compliance Mapping', description: 'NIST, PCI-DSS, HIPAA, SOC 2, ISO 27001 mapping', included: true },
      { id: 'normalization', name: 'Finding Normalization', description: 'Multi-scanner finding dedup and corroboration', included: true },
      { id: 'reporting_basic', name: 'Basic Reporting', description: 'VA and compliance reports', included: true },
      { id: 'pentest', name: 'Penetration Testing', description: 'Full pentest pipeline with exploitation', included: true },
      { id: 'purple_team', name: 'Purple Team', description: 'Detection assessment and bilateral timeline', included: true },
      { id: 'red_team', name: 'Red Team', description: 'Full adversary emulation with C2', included: true },
      { id: 'c2_integration', name: 'C2 Integration', description: 'Caldera/Sliver/Cobalt Strike integration', included: true },
      { id: 'post_exploit', name: 'Post-Exploitation', description: 'Automated post-exploitation pipeline', included: true },
    ],
    maxConcurrentEngagements: -1, // Unlimited
    maxTargetsPerEngagement: -1,  // Unlimited
    retentionDays: -1,            // Unlimited
    supportLevel: 'dedicated',
  },
};

// ─── Engagement Type Metadata ──────────────────────────────────────────────────

export interface EngagementTypeInfo {
  type: EngagementType;
  displayName: string;
  description: string;
  icon: string;                 // Lucide icon name
  requiredTier: LicenseTier;
  category: 'assessment' | 'offensive' | 'simulation' | 'research';
  capabilities: string[];
}

export const ENGAGEMENT_TYPE_INFO: Record<EngagementType, EngagementTypeInfo> = {
  vulnerability_assessment: {
    type: 'vulnerability_assessment',
    displayName: 'Vulnerability Assessment',
    description: 'Comprehensive multi-scanner vulnerability assessment with normalization, deduplication, and compliance mapping. No exploitation.',
    icon: 'Shield',
    requiredTier: 'standard',
    category: 'assessment',
    capabilities: [
      'Multi-scanner orchestration (Nuclei, ZAP, Burp, Trivy)',
      'Finding normalization and deduplication',
      'Verification profiles (PCI ASV, FedRAMP, HIPAA, SOC 2)',
      'Compliance framework mapping',
      'Risk prioritization with EPSS/KEV enrichment',
      'Remediation roadmap generation',
    ],
  },
  bug_bounty: {
    type: 'bug_bounty',
    displayName: 'Bug Bounty',
    description: 'Bug bounty research with program policy parsing, scope enforcement, finding documentation, and submission workflow.',
    icon: 'Bug',
    requiredTier: 'standard',
    category: 'research',
    capabilities: [
      'Program policy parsing (HackerOne, Bugcrowd, Intigriti)',
      'Scope enforcement and validation',
      'Finding documentation workflow',
      'Originality verification',
      'Platform-specific submission formatting',
      'Cross-training feedback loop',
    ],
  },
  phishing: {
    type: 'phishing',
    displayName: 'Phishing Campaign',
    description: 'GoPhish-integrated phishing simulation with email template design, landing pages, and campaign analytics.',
    icon: 'Mail',
    requiredTier: 'standard',
    category: 'simulation',
    capabilities: [
      'Email template design',
      'Landing page creation',
      'Campaign scheduling',
      'Click/credential tracking',
      'User awareness reporting',
    ],
  },
  tabletop: {
    type: 'tabletop',
    displayName: 'Tabletop Exercise',
    description: 'Scenario-based tabletop exercises for incident response planning and team coordination.',
    icon: 'Users',
    requiredTier: 'standard',
    category: 'simulation',
    capabilities: [
      'Scenario generation',
      'Inject scheduling',
      'Participant tracking',
      'Response assessment',
      'After-action reporting',
    ],
  },
  pentest: {
    type: 'pentest',
    displayName: 'Penetration Test',
    description: 'Full penetration testing pipeline with automated exploitation, post-exploitation, and comprehensive reporting.',
    icon: 'Crosshair',
    requiredTier: 'professional',
    category: 'offensive',
    capabilities: [
      'Full recon and enumeration pipeline',
      'Automated vulnerability detection',
      'Safe exploitation with evidence capture',
      'Post-exploitation enumeration',
      'Comprehensive pentest report',
      'Remediation guidance',
    ],
  },
  purple_team: {
    type: 'purple_team',
    displayName: 'Purple Team',
    description: 'Collaborative detection assessment with bilateral timeline, TTP mapping, and detection gap analysis.',
    icon: 'Swords',
    requiredTier: 'professional',
    category: 'offensive',
    capabilities: [
      'Detection test plan generation',
      'Bilateral timeline correlation',
      'Detection gap analysis',
      'MITRE ATT&CK mapping',
      'EDR/SIEM integration',
      'Detection improvement recommendations',
    ],
  },
  red_team: {
    type: 'red_team',
    displayName: 'Red Team',
    description: 'Full adversary emulation with C2 integration, advanced post-exploitation, and objective-based operations.',
    icon: 'Skull',
    requiredTier: 'enterprise',
    category: 'offensive',
    capabilities: [
      'C2 framework integration (Caldera, Sliver)',
      'Advanced post-exploitation',
      'Lateral movement automation',
      'Objective-based operations',
      'Adversary emulation plans',
      'Full kill chain reporting',
    ],
  },
};

// ─── Gating Functions ──────────────────────────────────────────────────────────

export interface GatingCheckResult {
  allowed: boolean;
  reason?: string;
  requiredTier?: LicenseTier;
  currentTier: LicenseTier;
  upgradeMessage?: string;
}

/**
 * Check if an engagement type is allowed for a given license tier.
 */
export function checkEngagementTypeAllowed(
  engagementType: EngagementType,
  currentTier: LicenseTier
): GatingCheckResult {
  const tierConfig = TIER_CONFIGS[currentTier];
  const typeInfo = ENGAGEMENT_TYPE_INFO[engagementType];
  
  if (!typeInfo) {
    return {
      allowed: false,
      reason: `Unknown engagement type: ${engagementType}`,
      currentTier,
    };
  }
  
  if (tierConfig.allowedEngagementTypes.includes(engagementType)) {
    return {
      allowed: true,
      currentTier,
    };
  }
  
  return {
    allowed: false,
    reason: `${typeInfo.displayName} requires ${TIER_CONFIGS[typeInfo.requiredTier].displayName} tier or higher`,
    requiredTier: typeInfo.requiredTier,
    currentTier,
    upgradeMessage: `Upgrade to ${TIER_CONFIGS[typeInfo.requiredTier].displayName} to unlock ${typeInfo.displayName} engagements. ${TIER_CONFIGS[typeInfo.requiredTier].description}`,
  };
}

/**
 * Check if the concurrent engagement limit is reached.
 */
export function checkConcurrentEngagementLimit(
  currentTier: LicenseTier,
  activeEngagementCount: number
): GatingCheckResult {
  const tierConfig = TIER_CONFIGS[currentTier];
  
  if (tierConfig.maxConcurrentEngagements === -1) {
    return { allowed: true, currentTier };
  }
  
  if (activeEngagementCount >= tierConfig.maxConcurrentEngagements) {
    return {
      allowed: false,
      reason: `Maximum concurrent engagements reached (${tierConfig.maxConcurrentEngagements})`,
      currentTier,
      upgradeMessage: `Upgrade to increase your concurrent engagement limit`,
    };
  }
  
  return { allowed: true, currentTier };
}

/**
 * Check if a specific feature is available for a tier.
 */
export function checkFeatureAvailable(
  featureId: string,
  currentTier: LicenseTier
): GatingCheckResult {
  const tierConfig = TIER_CONFIGS[currentTier];
  const feature = tierConfig.features.find(f => f.id === featureId);
  
  if (!feature) {
    return {
      allowed: false,
      reason: `Unknown feature: ${featureId}`,
      currentTier,
    };
  }
  
  if (feature.included) {
    return { allowed: true, currentTier };
  }
  
  // Find which tier includes this feature
  const tiers: LicenseTier[] = ['standard', 'professional', 'enterprise'];
  for (const tier of tiers) {
    const config = TIER_CONFIGS[tier];
    const f = config.features.find(f => f.id === featureId);
    if (f?.included) {
      return {
        allowed: false,
        reason: `${feature.name} requires ${config.displayName} tier`,
        requiredTier: tier,
        currentTier,
        upgradeMessage: `Upgrade to ${config.displayName} to unlock ${feature.name}`,
      };
    }
  }
  
  return {
    allowed: false,
    reason: `Feature ${featureId} is not available in any tier`,
    currentTier,
  };
}

/**
 * Get all available engagement types for a tier, with gating info for locked types.
 */
export function getAvailableEngagementTypes(currentTier: LicenseTier): Array<EngagementTypeInfo & { locked: boolean; lockReason?: string }> {
  return Object.values(ENGAGEMENT_TYPE_INFO).map(info => {
    const check = checkEngagementTypeAllowed(info.type, currentTier);
    return {
      ...info,
      locked: !check.allowed,
      lockReason: check.upgradeMessage,
    };
  });
}

/**
 * Get tier comparison data for upgrade prompts.
 */
export function getTierComparison(): Array<{
  tier: LicenseTier;
  displayName: string;
  description: string;
  engagementTypes: string[];
  keyFeatures: string[];
}> {
  return Object.values(TIER_CONFIGS).map(config => ({
    tier: config.tier,
    displayName: config.displayName,
    description: config.description,
    engagementTypes: config.allowedEngagementTypes,
    keyFeatures: config.features.filter(f => f.included).map(f => f.name),
  }));
}
