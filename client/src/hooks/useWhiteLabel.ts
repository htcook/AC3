/**
 * useWhiteLabel — Frontend hook for consuming white-label branding config.
 * 
 * Fetches the deployment's branding, feature toggles, and license info from
 * the server. Caches aggressively since branding doesn't change at runtime.
 * 
 * Usage:
 *   const { config, isFeatureEnabled, platformName, orgName } = useWhiteLabel();
 */
import { trpc } from "@/lib/trpc";
import { useMemo } from "react";

// ─── Types (mirrors server PublicWhiteLabelConfig) ───────────────────────────
export type LicenseTier = 'starter' | 'professional' | 'enterprise';

export type FeatureModule =
  | 'domain_intel'
  | 'adversary_emulation'
  | 'phishing_ops'
  | 'campaign_orchestrator'
  | 'vulnerability_scanner'
  | 'threat_catalog'
  | 'zero_day_tracker'
  | 'compliance_frameworks'
  | 'client_portal'
  | 'ai_security_validation'
  | 'ember_agents'
  | 'bounty_intel'
  | 'cicd_pipeline'
  | 'red_team_ops'
  | 'report_generator'
  | 'incident_search'
  | 'affiliated_domains'
  | 'training_feedback';

export interface WhiteLabelConfig {
  orgName: string;
  platformName: string;
  tagline: string;
  logoUrl: string;
  faviconUrl: string;
  supportEmail: string;
  supportUrl: string;
  websiteUrl: string;
  copyrightHolder: string;
  primaryColor: string;
  accentColor: string;
  sidebarBg: string;
  sidebarFg: string;
  licenseTier: LicenseTier;
  enabledFeatures: FeatureModule[];
  maxSeats: number;
  maxScansPerPeriod: number;
  reportCompanyName: string;
  reportAuthorName: string;
  reportLogoUrl: string;
  reportFooterText: string;
  reportDisclaimerText: string;
  deploymentId: string;
  environment: string;
}

// ─── Default Config (used before server responds) ────────────────────────────
const DEFAULT_CONFIG: WhiteLabelConfig = {
  orgName: 'AceofCloud',
  platformName: 'AC3',
  tagline: 'Cyber Campaign Command',
  logoUrl: '',
  faviconUrl: '',
  supportEmail: 'support@aceofcloud.com',
  supportUrl: 'https://aceofcloud.com/support',
  websiteUrl: 'https://aceofcloud.com',
  copyrightHolder: 'AceofCloud LLC',
  primaryColor: '',
  accentColor: '',
  sidebarBg: '',
  sidebarFg: '',
  licenseTier: 'enterprise',
  enabledFeatures: [],
  maxSeats: -1,
  maxScansPerPeriod: -1,
  reportCompanyName: 'AceofCloud',
  reportAuthorName: '',
  reportLogoUrl: '',
  reportFooterText: '',
  reportDisclaimerText: '',
  deploymentId: 'default',
  environment: 'development',
};

// ─── Hook ────────────────────────────────────────────────────────────────────
export function useWhiteLabel() {
  const { data, isLoading } = trpc.whiteLabel.getConfig.useQuery(undefined, {
    staleTime: 1000 * 60 * 60, // Cache for 1 hour — branding rarely changes
    refetchOnWindowFocus: false,
    refetchOnMount: false,
  });

  const config: WhiteLabelConfig = (data as WhiteLabelConfig) ?? DEFAULT_CONFIG;

  const enabledSet = useMemo(
    () => new Set(config.enabledFeatures),
    [config.enabledFeatures]
  );

  const isFeatureEnabled = (feature: FeatureModule): boolean => {
    // If no features loaded yet (still loading), allow everything
    if (enabledSet.size === 0 && isLoading) return true;
    return enabledSet.has(feature);
  };

  return {
    config,
    isLoading,
    isFeatureEnabled,
    // Convenience accessors
    platformName: config.platformName,
    orgName: config.orgName,
    tagline: config.tagline,
    logoUrl: config.logoUrl,
    supportEmail: config.supportEmail,
    licenseTier: config.licenseTier,
    copyrightHolder: config.copyrightHolder,
    reportCompanyName: config.reportCompanyName,
    reportAuthorName: config.reportAuthorName,
  };
}

// ─── Static Helper (for non-React contexts like report generation) ───────────
let _staticConfig: WhiteLabelConfig | null = null;

export function setStaticWhiteLabelConfig(config: WhiteLabelConfig) {
  _staticConfig = config;
}

export function getStaticWhiteLabelConfig(): WhiteLabelConfig {
  return _staticConfig ?? DEFAULT_CONFIG;
}
