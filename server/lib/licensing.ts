/**
 * Licensing System
 * ────────────────
 * JWT-based license key validation with feature gating, seat management,
 * usage metering, and tier enforcement.
 * 
 * License keys are signed JWTs containing:
 *   - org: Customer organization ID
 *   - orgName: Customer display name
 *   - tier: starter | professional | enterprise
 *   - features: explicit feature overrides (enable/disable beyond tier defaults)
 *   - seats: max concurrent users
 *   - scans: max scans per billing period (-1 = unlimited)
 *   - exp: expiry timestamp (Unix seconds)
 *   - iat: issued-at timestamp
 *   - iss: issuer identifier
 *   - sub: license subject (deployment ID)
 * 
 * Usage:
 *   const license = validateLicenseKey(key);
 *   if (!license.valid) throw new Error(license.error);
 *   if (!license.isFeatureAllowed('ember_agents')) throw new Error('Feature not licensed');
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import type { LicenseTier, FeatureModule } from './white-label';

// ─── License Signing Key ─────────────────────────────────────────────────────
// In production, this should be an RSA/EC key pair. The public key is embedded
// in the customer's deployment; the private key stays with AceofCloud for signing.
// Resolved once at module load so HS256 sign and verify use the same value in a
// process. No committed fallback — a static default would let anyone forge
// license tokens. Production requires an explicit secret; dev/test falls back to
// an ephemeral random secret (tokens won't survive a restart).
let cachedLicenseSigningSecret: string | undefined;
function getLicenseSigningSecret(): string {
  if (cachedLicenseSigningSecret !== undefined) return cachedLicenseSigningSecret;
  const secret = process.env.WL_LICENSE_SIGNING_SECRET ?? process.env.JWT_SECRET;
  if (secret && secret.length > 0) {
    cachedLicenseSigningSecret = secret;
  } else if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'WL_LICENSE_SIGNING_SECRET (or JWT_SECRET) is not set. Refusing to sign licenses with an insecure default in production.'
    );
  } else {
    cachedLicenseSigningSecret = crypto.randomBytes(48).toString('hex');
  }
  return cachedLicenseSigningSecret;
}

function getLicensePublicKey(): string {
  // For RS256/ES256, return the public key. For HS256 (dev), same as secret.
  return process.env.WL_LICENSE_PUBLIC_KEY ?? getLicenseSigningSecret();
}

// ─── License Claims Interface ────────────────────────────────────────────────
export interface LicenseClaims {
  org: string;           // Organization ID
  orgName: string;       // Display name
  tier: LicenseTier;     // License tier
  features?: Partial<Record<FeatureModule, boolean>>; // Feature overrides
  seats: number;         // Max seats (-1 = unlimited)
  scans: number;         // Max scans per period (-1 = unlimited)
  exp: number;           // Expiry (Unix seconds)
  iat: number;           // Issued at (Unix seconds)
  iss: string;           // Issuer
  sub: string;           // Subject (deployment ID)
  billingPeriodDays: number; // Billing cycle length
  gracePeriodDays: number;   // Grace period after expiry
}

// ─── Validation Result ───────────────────────────────────────────────────────
export interface LicenseValidationResult {
  valid: boolean;
  claims?: LicenseClaims;
  error?: string;
  isExpired: boolean;
  isInGracePeriod: boolean;
  daysUntilExpiry: number;
  isFeatureAllowed: (feature: FeatureModule) => boolean;
}

// ─── Usage Metering ──────────────────────────────────────────────────────────
interface UsageRecord {
  scans: number;
  reports: number;
  apiCalls: number;
  periodStart: number; // Unix ms
  periodEnd: number;   // Unix ms
}

// In-memory usage tracking (persisted to DB in production)
const _usageStore = new Map<string, UsageRecord>();

function getCurrentPeriod(billingPeriodDays: number): { start: number; end: number } {
  const now = Date.now();
  const periodMs = billingPeriodDays * 24 * 60 * 60 * 1000;
  // Align to billing period boundaries from epoch
  const periodStart = Math.floor(now / periodMs) * periodMs;
  const periodEnd = periodStart + periodMs;
  return { start: periodStart, end: periodEnd };
}

function getOrCreateUsage(orgId: string, billingPeriodDays: number): UsageRecord {
  const period = getCurrentPeriod(billingPeriodDays);
  const key = `${orgId}:${period.start}`;
  
  if (!_usageStore.has(key)) {
    _usageStore.set(key, {
      scans: 0,
      reports: 0,
      apiCalls: 0,
      periodStart: period.start,
      periodEnd: period.end,
    });
  }
  
  return _usageStore.get(key)!;
}

// ─── Tier Feature Matrix (mirrors white-label.ts) ────────────────────────────
const TIER_FEATURES: Record<LicenseTier, Set<FeatureModule>> = {
  starter: new Set([
    'domain_intel', 'threat_catalog', 'vulnerability_scanner',
    'report_generator', 'incident_search', 'affiliated_domains',
  ]),
  professional: new Set([
    'domain_intel', 'adversary_emulation', 'phishing_ops',
    'threat_catalog', 'vulnerability_scanner', 'zero_day_tracker',
    'compliance_frameworks', 'report_generator', 'incident_search',
    'affiliated_domains', 'training_feedback', 'bounty_intel', 'client_portal',
  ]),
  enterprise: new Set([
    'domain_intel', 'adversary_emulation', 'phishing_ops',
    'campaign_orchestrator', 'vulnerability_scanner', 'threat_catalog',
    'zero_day_tracker', 'compliance_frameworks', 'client_portal',
    'ai_security_validation', 'ember_agents', 'bounty_intel',
    'cicd_pipeline', 'red_team_ops', 'report_generator',
    'incident_search', 'affiliated_domains', 'training_feedback',
  ]),
};

// ─── Validate License Key ────────────────────────────────────────────────────
export function validateLicenseKey(licenseKey: string): LicenseValidationResult {
  const noLicenseResult: LicenseValidationResult = {
    valid: false,
    isExpired: false,
    isInGracePeriod: false,
    daysUntilExpiry: 0,
    error: 'No license key provided',
    isFeatureAllowed: () => false,
  };

  if (!licenseKey) return noLicenseResult;

  try {
    const publicKey = getLicensePublicKey();
    const decoded = jwt.verify(licenseKey, publicKey, {
      issuer: 'aceofcloud-licensing',
      // Allow expired tokens so we can check grace period
      clockTolerance: 0,
    }) as LicenseClaims;

    const now = Math.floor(Date.now() / 1000);
    const isExpired = now > decoded.exp;
    const gracePeriodSeconds = (decoded.gracePeriodDays ?? 7) * 24 * 60 * 60;
    const isInGracePeriod = isExpired && now <= (decoded.exp + gracePeriodSeconds);
    const daysUntilExpiry = Math.ceil((decoded.exp - now) / (24 * 60 * 60));

    // Feature check function
    const isFeatureAllowed = (feature: FeatureModule): boolean => {
      // Explicit overrides take priority
      if (decoded.features?.[feature] === true) return true;
      if (decoded.features?.[feature] === false) return false;
      // Fall back to tier defaults
      return TIER_FEATURES[decoded.tier]?.has(feature) ?? false;
    };

    // License is valid if not expired, or in grace period
    const valid = !isExpired || isInGracePeriod;

    return {
      valid,
      claims: decoded,
      isExpired,
      isInGracePeriod,
      daysUntilExpiry,
      isFeatureAllowed,
      error: isExpired && !isInGracePeriod
        ? `License expired ${Math.abs(daysUntilExpiry)} days ago. Grace period has ended.`
        : isInGracePeriod
        ? `License expired. Grace period ends in ${Math.ceil((decoded.exp + gracePeriodSeconds - now) / (24 * 60 * 60))} days.`
        : undefined,
    };
  } catch (err: any) {
    // Handle expired token separately to check grace period
    if (err.name === 'TokenExpiredError') {
      try {
        const decoded = jwt.decode(licenseKey) as LicenseClaims;
        if (decoded) {
          const now = Math.floor(Date.now() / 1000);
          const gracePeriodSeconds = (decoded.gracePeriodDays ?? 7) * 24 * 60 * 60;
          const isInGracePeriod = now <= (decoded.exp + gracePeriodSeconds);
          const daysUntilExpiry = Math.ceil((decoded.exp - now) / (24 * 60 * 60));

          if (isInGracePeriod) {
            const isFeatureAllowed = (feature: FeatureModule): boolean => {
              if (decoded.features?.[feature] === true) return true;
              if (decoded.features?.[feature] === false) return false;
              return TIER_FEATURES[decoded.tier]?.has(feature) ?? false;
            };

            return {
              valid: true,
              claims: decoded,
              isExpired: true,
              isInGracePeriod: true,
              daysUntilExpiry,
              isFeatureAllowed,
              error: `License expired. Grace period ends in ${Math.ceil((decoded.exp + gracePeriodSeconds - now) / (24 * 60 * 60))} days.`,
            };
          }
        }
      } catch { /* ignore decode errors */ }
    }

    return {
      valid: false,
      isExpired: err.name === 'TokenExpiredError',
      isInGracePeriod: false,
      daysUntilExpiry: 0,
      error: err.name === 'TokenExpiredError'
        ? 'License has expired and grace period has ended.'
        : `Invalid license key: ${err.message}`,
      isFeatureAllowed: () => false,
    };
  }
}

// ─── Generate License Key (Admin/CLI tool) ───────────────────────────────────
export interface GenerateLicenseOptions {
  org: string;
  orgName: string;
  tier: LicenseTier;
  features?: Partial<Record<FeatureModule, boolean>>;
  seats?: number;
  scans?: number;
  expiryDays?: number;
  billingPeriodDays?: number;
  gracePeriodDays?: number;
  deploymentId?: string;
}

export function generateLicenseKey(options: GenerateLicenseOptions): string {
  const secret = getLicenseSigningSecret();
  const now = Math.floor(Date.now() / 1000);
  const expiryDays = options.expiryDays ?? 365;

  const claims: LicenseClaims = {
    org: options.org,
    orgName: options.orgName,
    tier: options.tier,
    features: options.features,
    seats: options.seats ?? (options.tier === 'starter' ? 5 : options.tier === 'professional' ? 25 : -1),
    scans: options.scans ?? (options.tier === 'starter' ? 50 : options.tier === 'professional' ? 500 : -1),
    exp: now + (expiryDays * 24 * 60 * 60),
    iat: now,
    iss: 'aceofcloud-licensing',
    sub: options.deploymentId ?? `deploy-${options.org}`,
    billingPeriodDays: options.billingPeriodDays ?? 30,
    gracePeriodDays: options.gracePeriodDays ?? 7,
  };

  return jwt.sign(claims, secret, { algorithm: 'HS256' });
}

// ─── Usage Metering Functions ────────────────────────────────────────────────
export function recordScanUsage(orgId: string, billingPeriodDays: number = 30): UsageRecord {
  const usage = getOrCreateUsage(orgId, billingPeriodDays);
  usage.scans++;
  return usage;
}

export function recordReportUsage(orgId: string, billingPeriodDays: number = 30): UsageRecord {
  const usage = getOrCreateUsage(orgId, billingPeriodDays);
  usage.reports++;
  return usage;
}

export function recordApiCallUsage(orgId: string, billingPeriodDays: number = 30): UsageRecord {
  const usage = getOrCreateUsage(orgId, billingPeriodDays);
  usage.apiCalls++;
  return usage;
}

export function getUsage(orgId: string, billingPeriodDays: number = 30): UsageRecord {
  return getOrCreateUsage(orgId, billingPeriodDays);
}

export function isWithinScanLimit(orgId: string, claims: LicenseClaims): boolean {
  if (claims.scans === -1) return true; // unlimited
  const usage = getOrCreateUsage(orgId, claims.billingPeriodDays);
  return usage.scans < claims.scans;
}

// ─── License Status Summary ──────────────────────────────────────────────────
export interface LicenseStatus {
  valid: boolean;
  tier: LicenseTier;
  orgName: string;
  isExpired: boolean;
  isInGracePeriod: boolean;
  daysUntilExpiry: number;
  enabledFeatures: FeatureModule[];
  usage: {
    scans: { used: number; limit: number; remaining: number };
    seats: { limit: number };
    periodStart: string;
    periodEnd: string;
  };
  warnings: string[];
}

export function getLicenseStatus(): LicenseStatus {
  const licenseKey = process.env.WL_LICENSE_KEY ?? '';
  const result = validateLicenseKey(licenseKey);

  const warnings: string[] = [];
  if (!result.valid && !licenseKey) {
    // No license key — running in dev/unlicensed mode
    return {
      valid: false,
      tier: 'enterprise',
      orgName: 'Development Mode',
      isExpired: false,
      isInGracePeriod: false,
      daysUntilExpiry: -1,
      enabledFeatures: Array.from(TIER_FEATURES.enterprise),
      usage: {
        scans: { used: 0, limit: -1, remaining: -1 },
        seats: { limit: -1 },
        periodStart: new Date().toISOString(),
        periodEnd: new Date().toISOString(),
      },
      warnings: ['No license key configured. Running in development mode with all features enabled.'],
    };
  }

  if (!result.valid) {
    return {
      valid: false,
      tier: 'starter',
      orgName: result.claims?.orgName ?? 'Unknown',
      isExpired: result.isExpired,
      isInGracePeriod: result.isInGracePeriod,
      daysUntilExpiry: result.daysUntilExpiry,
      enabledFeatures: [],
      usage: {
        scans: { used: 0, limit: 0, remaining: 0 },
        seats: { limit: 0 },
        periodStart: new Date().toISOString(),
        periodEnd: new Date().toISOString(),
      },
      warnings: [result.error ?? 'License validation failed'],
    };
  }

  const claims = result.claims!;
  const usage = getOrCreateUsage(claims.org, claims.billingPeriodDays);

  // Build enabled features list
  const allFeatures: FeatureModule[] = [
    'domain_intel', 'adversary_emulation', 'phishing_ops', 'campaign_orchestrator',
    'vulnerability_scanner', 'threat_catalog', 'zero_day_tracker', 'compliance_frameworks',
    'client_portal', 'ai_security_validation', 'ember_agents', 'bounty_intel',
    'cicd_pipeline', 'red_team_ops', 'report_generator', 'incident_search',
    'affiliated_domains', 'training_feedback',
  ];
  const enabledFeatures = allFeatures.filter(f => result.isFeatureAllowed(f));

  // Warnings
  if (result.isInGracePeriod) {
    warnings.push(result.error!);
  }
  if (result.daysUntilExpiry <= 30 && result.daysUntilExpiry > 0) {
    warnings.push(`License expires in ${result.daysUntilExpiry} days. Please renew.`);
  }
  if (claims.scans !== -1 && usage.scans >= claims.scans * 0.8) {
    const remaining = claims.scans - usage.scans;
    warnings.push(`${remaining} scans remaining in this billing period.`);
  }

  return {
    valid: true,
    tier: claims.tier,
    orgName: claims.orgName,
    isExpired: result.isExpired,
    isInGracePeriod: result.isInGracePeriod,
    daysUntilExpiry: result.daysUntilExpiry,
    enabledFeatures,
    usage: {
      scans: {
        used: usage.scans,
        limit: claims.scans,
        remaining: claims.scans === -1 ? -1 : Math.max(0, claims.scans - usage.scans),
      },
      seats: { limit: claims.seats },
      periodStart: new Date(usage.periodStart).toISOString(),
      periodEnd: new Date(usage.periodEnd).toISOString(),
    },
    warnings,
  };
}
