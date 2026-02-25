/**
 * Domain Reputation & Categorization Engine
 * 
 * Based on Red Team Infrastructure Wiki principles:
 *   - Expired domain acquisition with reputation scoring
 *   - Categorization checking across security vendors (McAfee, Fortiguard, Symantec, etc.)
 *   - Domain age, backlink profile, and web archive analysis
 *   - Finance/Healthcare categorization to avoid SSL interception
 * 
 * Provides:
 *   - Domain reputation scoring (0-100)
 *   - Multi-vendor categorization lookup
 *   - Expired domain candidate ranking
 *   - Domain health monitoring for active operations
 */

export type DomainCategory = 
  | "uncategorized" | "business" | "technology" | "finance" | "healthcare"
  | "education" | "government" | "news" | "social_media" | "shopping"
  | "entertainment" | "adult" | "malware" | "phishing" | "suspicious"
  | "cdn" | "cloud_services" | "parked";

export type VendorName = 
  | "mcafee_trustedsource" | "fortiguard" | "symantec_bluecoat" 
  | "palo_alto" | "checkpoint" | "cisco_talos" | "zscaler"
  | "websense" | "barracuda" | "sophos";

export interface VendorCategorization {
  vendor: VendorName;
  category: DomainCategory;
  confidence: number; // 0-100
  lastChecked: number;
  risk: "clean" | "low" | "medium" | "high" | "malicious";
}

export interface DomainReputationProfile {
  domain: string;
  overallScore: number; // 0-100 (higher = better reputation for red team use)
  age: {
    registrationDate?: string;
    expirationDate?: string;
    ageDays: number;
    isExpired: boolean;
  };
  categorizations: VendorCategorization[];
  /** Dominant category across vendors */
  primaryCategory: DomainCategory;
  /** Whether the domain is categorized in a "safe" category (finance/healthcare/business) */
  hasSafeCategory: boolean;
  /** Web archive presence (Wayback Machine snapshots) */
  webArchive: {
    hasHistory: boolean;
    firstSeen?: string;
    lastSeen?: string;
    snapshotCount: number;
  };
  /** Backlink profile indicators */
  backlinks: {
    estimatedCount: number;
    hasAuthoritativeLinks: boolean;
    topReferrers: string[];
  };
  /** DNS configuration */
  dns: {
    hasARecord: boolean;
    hasMxRecord: boolean;
    hasSpfRecord: boolean;
    hasDkimRecord: boolean;
    hasDmarcRecord: boolean;
    nameservers: string[];
  };
  /** SSL/TLS information */
  ssl: {
    hasCertificate: boolean;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    grade?: string;
  };
  /** Red team suitability assessment */
  suitability: {
    phishingScore: number; // 0-100
    c2Score: number; // 0-100
    payloadHostingScore: number; // 0-100
    recommendations: string[];
    warnings: string[];
  };
  lastUpdated: number;
}

export interface ExpiredDomainCandidate {
  domain: string;
  tld: string;
  expiredDate: string;
  previousCategory?: DomainCategory;
  domainAge: number; // days
  backlinks: number;
  webArchiveSnapshots: number;
  /** Composite ranking score for red team use */
  rankScore: number; // 0-100
  /** Why this domain is a good candidate */
  strengths: string[];
  /** Potential issues */
  risks: string[];
}

// ── In-memory store ────────────────────────────────────────────────────

const profiles = new Map<string, DomainReputationProfile>();
const candidates = new Map<string, ExpiredDomainCandidate>();
const monitoredDomains = new Set<string>();

// ── Vendor Categorization Simulation ───────────────────────────────────

const VENDOR_DISPLAY_NAMES: Record<VendorName, string> = {
  mcafee_trustedsource: "McAfee TrustedSource",
  fortiguard: "FortiGuard Web Filter",
  symantec_bluecoat: "Symantec/BlueCoat",
  palo_alto: "Palo Alto URL Filtering",
  checkpoint: "Check Point URL Filtering",
  cisco_talos: "Cisco Talos Intelligence",
  zscaler: "Zscaler URL Category",
  websense: "Websense/Forcepoint",
  barracuda: "Barracuda Web Filter",
  sophos: "Sophos Web Intelligence",
};

export function getVendorDisplayName(vendor: VendorName): string {
  return VENDOR_DISPLAY_NAMES[vendor] || vendor;
}

const SAFE_CATEGORIES: DomainCategory[] = ["finance", "healthcare", "business", "education", "government", "technology"];

function simulateVendorCheck(domain: string, vendor: VendorName): VendorCategorization {
  // Deterministic simulation based on domain hash
  const hash = simpleHash(domain + vendor);
  const categories: DomainCategory[] = ["business", "technology", "uncategorized", "finance", "healthcare", "education", "news", "shopping"];
  const category = categories[hash % categories.length];
  const confidence = 60 + (hash % 40);
  
  return {
    vendor,
    category,
    confidence,
    lastChecked: Date.now(),
    risk: category === "uncategorized" ? "low" : "clean",
  };
}

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash);
}

// ── Core Analysis Functions ────────────────────────────────────────────

export function analyzeDomain(domain: string): DomainReputationProfile {
  const existing = profiles.get(domain);
  if (existing && Date.now() - existing.lastUpdated < 3600000) {
    return existing; // Cache for 1 hour
  }

  const hash = simpleHash(domain);
  
  // Check all vendors
  const vendors: VendorName[] = [
    "mcafee_trustedsource", "fortiguard", "symantec_bluecoat",
    "palo_alto", "checkpoint", "cisco_talos", "zscaler",
    "websense", "barracuda", "sophos",
  ];
  
  const categorizations = vendors.map(v => simulateVendorCheck(domain, v));
  
  // Determine primary category (most common across vendors)
  const categoryCounts = new Map<DomainCategory, number>();
  for (const cat of categorizations) {
    categoryCounts.set(cat.category, (categoryCounts.get(cat.category) ?? 0) + 1);
  }
  let primaryCategory: DomainCategory = "uncategorized";
  let maxCount = 0;
  for (const [cat, count] of Array.from(categoryCounts.entries())) {
    if (count > maxCount) { maxCount = count; primaryCategory = cat; }
  }

  const hasSafeCategory = SAFE_CATEGORIES.includes(primaryCategory);
  const ageDays = 365 + (hash % 3650);
  const isExpired = hash % 10 < 2;

  // Calculate suitability scores
  const phishingScore = calculatePhishingScore(ageDays, hasSafeCategory, categorizations);
  const c2Score = calculateC2Score(ageDays, primaryCategory, categorizations);
  const payloadScore = calculatePayloadScore(ageDays, hasSafeCategory);

  const recommendations: string[] = [];
  const warnings: string[] = [];

  if (hasSafeCategory) {
    recommendations.push(`Domain categorized as "${primaryCategory}" — less likely to be SSL-intercepted`);
  }
  if (ageDays > 365) {
    recommendations.push(`Domain age ${Math.floor(ageDays / 365)}+ years — established reputation`);
  }
  if (primaryCategory === "uncategorized") {
    warnings.push("Domain is uncategorized — may trigger security alerts on first use");
  }
  if (ageDays < 30) {
    warnings.push("Recently registered domain — high suspicion score at most security vendors");
  }

  const profile: DomainReputationProfile = {
    domain,
    overallScore: Math.round((phishingScore + c2Score + payloadScore) / 3),
    age: {
      registrationDate: new Date(Date.now() - ageDays * 86400000).toISOString().split("T")[0],
      expirationDate: isExpired ? new Date(Date.now() - (hash % 365) * 86400000).toISOString().split("T")[0] : new Date(Date.now() + 365 * 86400000).toISOString().split("T")[0],
      ageDays,
      isExpired,
    },
    categorizations,
    primaryCategory,
    hasSafeCategory,
    webArchive: {
      hasHistory: ageDays > 180,
      firstSeen: ageDays > 180 ? new Date(Date.now() - ageDays * 86400000).toISOString().split("T")[0] : undefined,
      lastSeen: ageDays > 180 ? new Date(Date.now() - (hash % 90) * 86400000).toISOString().split("T")[0] : undefined,
      snapshotCount: ageDays > 180 ? 10 + (hash % 500) : 0,
    },
    backlinks: {
      estimatedCount: hash % 10000,
      hasAuthoritativeLinks: hash % 5 < 2,
      topReferrers: generateTopReferrers(hash),
    },
    dns: {
      hasARecord: !isExpired,
      hasMxRecord: hash % 3 < 2,
      hasSpfRecord: hash % 4 < 2,
      hasDkimRecord: hash % 5 < 2,
      hasDmarcRecord: hash % 6 < 2,
      nameservers: isExpired ? [] : [`ns1.${domain}`, `ns2.${domain}`],
    },
    ssl: {
      hasCertificate: !isExpired && hash % 3 < 2,
      issuer: hash % 3 < 2 ? "Let's Encrypt Authority X3" : undefined,
      grade: hash % 3 < 2 ? (hash % 2 === 0 ? "A" : "B") : undefined,
    },
    suitability: {
      phishingScore,
      c2Score,
      payloadHostingScore: payloadScore,
      recommendations,
      warnings,
    },
    lastUpdated: Date.now(),
  };

  profiles.set(domain, profile);
  return profile;
}

function calculatePhishingScore(ageDays: number, hasSafe: boolean, cats: VendorCategorization[]): number {
  let score = 50;
  if (ageDays > 365) score += 15;
  if (ageDays > 1825) score += 10;
  if (hasSafe) score += 15;
  const cleanCount = cats.filter(c => c.risk === "clean").length;
  score += Math.min(cleanCount * 2, 10);
  return Math.min(score, 100);
}

function calculateC2Score(ageDays: number, primary: DomainCategory, cats: VendorCategorization[]): number {
  let score = 40;
  if (ageDays > 180) score += 10;
  if (primary === "technology" || primary === "cdn" || primary === "cloud_services") score += 20;
  if (primary === "business") score += 10;
  const cleanCount = cats.filter(c => c.risk === "clean").length;
  score += Math.min(cleanCount * 2, 10);
  return Math.min(score, 100);
}

function calculatePayloadScore(ageDays: number, hasSafe: boolean): number {
  let score = 45;
  if (ageDays > 365) score += 15;
  if (hasSafe) score += 15;
  return Math.min(score, 100);
}

function generateTopReferrers(hash: number): string[] {
  const referrers = ["google.com", "bing.com", "linkedin.com", "twitter.com", "reddit.com", "github.com", "stackoverflow.com", "medium.com"];
  const count = 1 + (hash % 4);
  return referrers.slice(0, count);
}

// ── Expired Domain Candidates ──────────────────────────────────────────

export function rankExpiredDomainCandidates(domains: string[]): ExpiredDomainCandidate[] {
  const results: ExpiredDomainCandidate[] = [];

  for (const domain of domains) {
    const hash = simpleHash(domain);
    const parts = domain.split(".");
    const tld = parts[parts.length - 1];
    const ageDays = 365 + (hash % 3650);
    const backlinks = hash % 10000;
    const snapshots = 10 + (hash % 500);

    const strengths: string[] = [];
    const risks: string[] = [];

    if (ageDays > 1825) strengths.push("5+ year domain age — established trust");
    if (ageDays > 365) strengths.push("1+ year domain age");
    if (backlinks > 1000) strengths.push(`${backlinks} backlinks — strong link profile`);
    if (snapshots > 100) strengths.push(`${snapshots} web archive snapshots — rich history`);
    if (tld === "com" || tld === "org" || tld === "net") strengths.push(`${tld} TLD — high trust`);

    if (ageDays < 180) risks.push("Recently expired — may still be flagged");
    if (backlinks < 50) risks.push("Low backlink count — limited reputation");
    if (tld === "xyz" || tld === "tk" || tld === "ml") risks.push(`${tld} TLD — commonly associated with abuse`);

    // Composite ranking
    let rankScore = 30;
    if (ageDays > 365) rankScore += 15;
    if (ageDays > 1825) rankScore += 10;
    if (backlinks > 500) rankScore += 15;
    if (backlinks > 5000) rankScore += 10;
    if (snapshots > 50) rankScore += 10;
    if (["com", "org", "net"].includes(tld)) rankScore += 10;
    rankScore = Math.min(rankScore, 100);

    const candidate: ExpiredDomainCandidate = {
      domain,
      tld,
      expiredDate: new Date(Date.now() - (hash % 365) * 86400000).toISOString().split("T")[0],
      previousCategory: ["business", "technology", "education", "news"][hash % 4] as DomainCategory,
      domainAge: ageDays,
      backlinks,
      webArchiveSnapshots: snapshots,
      rankScore,
      strengths,
      risks,
    };

    candidates.set(domain, candidate);
    results.push(candidate);
  }

  return results.sort((a, b) => b.rankScore - a.rankScore);
}

// ── Domain Monitoring ──────────────────────────────────────────────────

export function addToMonitoring(domain: string): void {
  monitoredDomains.add(domain);
}

export function removeFromMonitoring(domain: string): void {
  monitoredDomains.delete(domain);
}

export function getMonitoredDomains(): string[] {
  return Array.from(monitoredDomains);
}

export function checkMonitoredDomains(): DomainReputationProfile[] {
  return Array.from(monitoredDomains).map(d => analyzeDomain(d));
}

// ── Getters ────────────────────────────────────────────────────────────

export function getProfile(domain: string): DomainReputationProfile | undefined {
  return profiles.get(domain);
}

export function listProfiles(): DomainReputationProfile[] {
  return Array.from(profiles.values()).sort((a, b) => b.lastUpdated - a.lastUpdated);
}

// ── Reset (for testing) ────────────────────────────────────────────────

export function _resetForTesting(): void {
  profiles.clear();
  candidates.clear();
  monitoredDomains.clear();
}
