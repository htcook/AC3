/**
 * White-Label Configuration Module
 * ─────────────────────────────────
 * Centralizes all branding, feature toggles, and deployment-specific settings.
 * Customers override defaults via environment variables prefixed with WL_.
 * 
 * The server serves this config via a public tRPC endpoint so the frontend
 * can render the correct branding without hardcoding anything.
 */

// ─── License Tier Definitions ────────────────────────────────────────────────
export type LicenseTier = 'starter' | 'professional' | 'enterprise';

// ─── Feature Module Definitions ──────────────────────────────────────────────
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

// ─── Feature Matrix by Tier ──────────────────────────────────────────────────
const TIER_FEATURES: Record<LicenseTier, FeatureModule[]> = {
  starter: [
    'domain_intel',
    'threat_catalog',
    'vulnerability_scanner',
    'report_generator',
    'incident_search',
    'affiliated_domains',
  ],
  professional: [
    'domain_intel',
    'adversary_emulation',
    'phishing_ops',
    'threat_catalog',
    'vulnerability_scanner',
    'zero_day_tracker',
    'compliance_frameworks',
    'report_generator',
    'incident_search',
    'affiliated_domains',
    'training_feedback',
    'bounty_intel',
    'client_portal',
  ],
  enterprise: [
    'domain_intel',
    'adversary_emulation',
    'phishing_ops',
    'campaign_orchestrator',
    'vulnerability_scanner',
    'threat_catalog',
    'zero_day_tracker',
    'compliance_frameworks',
    'client_portal',
    'ai_security_validation',
    'ember_agents',
    'bounty_intel',
    'cicd_pipeline',
    'red_team_ops',
    'report_generator',
    'incident_search',
    'affiliated_domains',
    'training_feedback',
  ],
};

// ─── Seat Limits by Tier ─────────────────────────────────────────────────────
const TIER_SEAT_LIMITS: Record<LicenseTier, number> = {
  starter: 5,
  professional: 25,
  enterprise: -1, // unlimited
};

// ─── Scan Limits by Tier (per billing period) ────────────────────────────────
const TIER_SCAN_LIMITS: Record<LicenseTier, number> = {
  starter: 50,
  professional: 500,
  enterprise: -1, // unlimited
};

// ─── White-Label Config Interface ────────────────────────────────────────────
export interface WhiteLabelConfig {
  // Branding
  orgName: string;
  platformName: string;
  tagline: string;
  logoUrl: string;
  faviconUrl: string;
  supportEmail: string;
  supportUrl: string;
  websiteUrl: string;
  copyrightHolder: string;

  // Colors (CSS custom property values)
  primaryColor: string;
  accentColor: string;
  sidebarBg: string;
  sidebarFg: string;

  // Deployment
  deploymentId: string;
  deploymentDomain: string;
  environment: 'production' | 'staging' | 'development';

  // License
  licenseTier: LicenseTier;
  enabledFeatures: FeatureModule[];
  maxSeats: number;
  maxScansPerPeriod: number;

  // Feature Toggles (granular overrides beyond tier)
  featureOverrides: Partial<Record<FeatureModule, boolean>>;

  // Custom integrations
  customC2Url: string;
  customGophishUrl: string;
  customScanServerHost: string;

  // Report branding
  reportCompanyName: string;
  reportAuthorName: string;
  reportLogoUrl: string;
  reportFooterText: string;
  reportDisclaimerText: string;
}

// ─── Parse Feature Overrides from Env ────────────────────────────────────────
function parseFeatureOverrides(): Partial<Record<FeatureModule, boolean>> {
  const raw = process.env.WL_FEATURE_OVERRIDES ?? '';
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    // Format: "domain_intel:true,ember_agents:false"
    const overrides: Partial<Record<FeatureModule, boolean>> = {};
    raw.split(',').forEach(pair => {
      const [key, val] = pair.trim().split(':');
      if (key && val) {
        overrides[key.trim() as FeatureModule] = val.trim() === 'true';
      }
    });
    return overrides;
  }
}

// ─── Resolve Enabled Features ────────────────────────────────────────────────
function resolveEnabledFeatures(tier: LicenseTier, overrides: Partial<Record<FeatureModule, boolean>>): FeatureModule[] {
  const tierFeatures = new Set(TIER_FEATURES[tier] ?? TIER_FEATURES.enterprise);

  // Apply overrides
  for (const [feature, enabled] of Object.entries(overrides)) {
    if (enabled) {
      tierFeatures.add(feature as FeatureModule);
    } else {
      tierFeatures.delete(feature as FeatureModule);
    }
  }

  return Array.from(tierFeatures);
}

// ─── Build White-Label Config ────────────────────────────────────────────────
let _cachedConfig: WhiteLabelConfig | null = null;

export function getWhiteLabelConfig(): WhiteLabelConfig {
  if (_cachedConfig) return _cachedConfig;

  const tier = (process.env.WL_LICENSE_TIER ?? 'enterprise') as LicenseTier;
  const overrides = parseFeatureOverrides();
  const enabledFeatures = resolveEnabledFeatures(tier, overrides);

  _cachedConfig = {
    // Branding
    orgName: process.env.WL_ORG_NAME ?? 'AceofCloud',
    platformName: process.env.WL_PLATFORM_NAME ?? 'AC3',
    tagline: process.env.WL_TAGLINE ?? 'Cyber Campaign Command',
    logoUrl: process.env.WL_LOGO_URL ?? '',
    faviconUrl: process.env.WL_FAVICON_URL ?? '',
    supportEmail: process.env.WL_SUPPORT_EMAIL ?? 'support@aceofcloud.com',
    supportUrl: process.env.WL_SUPPORT_URL ?? 'https://aceofcloud.com/support',
    websiteUrl: process.env.WL_WEBSITE_URL ?? 'https://aceofcloud.com',
    copyrightHolder: process.env.WL_COPYRIGHT_HOLDER ?? 'AceofCloud LLC',

    // Colors
    primaryColor: process.env.WL_PRIMARY_COLOR ?? 'oklch(0.7 0.15 250)',
    accentColor: process.env.WL_ACCENT_COLOR ?? 'oklch(0.65 0.2 160)',
    sidebarBg: process.env.WL_SIDEBAR_BG ?? '',
    sidebarFg: process.env.WL_SIDEBAR_FG ?? '',

    // Deployment
    deploymentId: process.env.WL_DEPLOYMENT_ID ?? 'default',
    deploymentDomain: process.env.WL_DEPLOYMENT_DOMAIN ?? '',
    environment: (process.env.NODE_ENV ?? 'development') as 'production' | 'staging' | 'development',

    // License
    licenseTier: tier,
    enabledFeatures,
    maxSeats: TIER_SEAT_LIMITS[tier] ?? -1,
    maxScansPerPeriod: TIER_SCAN_LIMITS[tier] ?? -1,

    // Feature overrides
    featureOverrides: overrides,

    // Custom integrations
    customC2Url: process.env.WL_C2_URL ?? '',
    customGophishUrl: process.env.WL_GOPHISH_URL ?? '',
    customScanServerHost: process.env.WL_SCAN_SERVER_HOST ?? '',

    // Report branding
    reportCompanyName: process.env.WL_REPORT_COMPANY_NAME ?? process.env.WL_ORG_NAME ?? 'AceofCloud',
    reportAuthorName: process.env.WL_REPORT_AUTHOR_NAME ?? '',
    reportLogoUrl: process.env.WL_REPORT_LOGO_URL ?? process.env.WL_LOGO_URL ?? '',
    reportFooterText: process.env.WL_REPORT_FOOTER ?? '',
    reportDisclaimerText: process.env.WL_REPORT_DISCLAIMER ?? '',
  };

  return _cachedConfig;
}

// ─── Reset Cache (for testing) ───────────────────────────────────────────────
export function resetWhiteLabelCache(): void {
  _cachedConfig = null;
}

// ─── Feature Check Helper ────────────────────────────────────────────────────
export function isFeatureEnabled(feature: FeatureModule): boolean {
  const config = getWhiteLabelConfig();
  return config.enabledFeatures.includes(feature);
}

// ─── Public Config (safe to send to frontend — no secrets) ───────────────────
export interface PublicWhiteLabelConfig {
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

export function getPublicWhiteLabelConfig(): PublicWhiteLabelConfig {
  const c = getWhiteLabelConfig();
  return {
    orgName: c.orgName,
    platformName: c.platformName,
    tagline: c.tagline,
    logoUrl: c.logoUrl,
    faviconUrl: c.faviconUrl,
    supportEmail: c.supportEmail,
    supportUrl: c.supportUrl,
    websiteUrl: c.websiteUrl,
    copyrightHolder: c.copyrightHolder,
    primaryColor: c.primaryColor,
    accentColor: c.accentColor,
    sidebarBg: c.sidebarBg,
    sidebarFg: c.sidebarFg,
    licenseTier: c.licenseTier,
    enabledFeatures: c.enabledFeatures,
    maxSeats: c.maxSeats,
    maxScansPerPeriod: c.maxScansPerPeriod,
    reportCompanyName: c.reportCompanyName,
    reportAuthorName: c.reportAuthorName,
    reportLogoUrl: c.reportLogoUrl,
    reportFooterText: c.reportFooterText,
    reportDisclaimerText: c.reportDisclaimerText,
    deploymentId: c.deploymentId,
    environment: c.environment,
  };
}
