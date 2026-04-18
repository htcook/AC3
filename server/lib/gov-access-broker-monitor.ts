/**
 * US Government Access Broker Monitor
 *
 * Monitors, correlates, and enriches Initial Access Broker (IAB) listings
 * targeting US government entities (.gov, .mil, federal agencies, SLTT).
 *
 * Intelligence sources:
 *   - Rapid7 H2 2025: Government is #1 targeted sector (14.2%)
 *   - DarkForums, RAMP, Exploit, BreachForums, XSS forum patterns
 *   - CISA advisories on IAB activity (AA24-241A, AA25-071A)
 *   - Known IAB groups: Pioneer Kitten, Exotic Lily, Scattered Spider
 */

// ─── Known IAB Knowledge Base ────────────────────────────────────────────

export interface GovIabProfile {
  brokerId: string;
  brokerName: string;
  aliases: string[];
  attribution: string;
  sponsorship: "state-sponsored" | "cybercrime" | "hybrid" | "unknown";
  primaryForums: string[];
  accessTypes: string[];
  govTargeting: {
    agencies: string[];
    domains: string[];
    accessMethods: string[];
    priceRange: { min: number; max: number; currency: string };
  };
  linkedGroups: string[];
  mitreTechniques: string[];
  cisaAdvisories: string[];
  riskScore: number;
  lastActive: string;
  notes: string;
}

/**
 * Curated knowledge base of known IABs targeting US government.
 * Sourced from Rapid7, CISA, Mandiant, CrowdStrike, and open-source intelligence.
 */
export const GOV_IAB_KNOWLEDGE_BASE: GovIabProfile[] = [
  {
    brokerId: "iab-pioneer-kitten",
    brokerName: "Pioneer Kitten",
    aliases: ["UNC757", "Parisite", "Rubidium", "Lemon Sandstorm", "Fox Kitten"],
    attribution: "Iran (MOIS)",
    sponsorship: "state-sponsored",
    primaryForums: ["Exploit", "RAMP"],
    accessTypes: ["vpn_access", "rdp_access", "citrix_access"],
    govTargeting: {
      agencies: ["Defense Industrial Base", "Federal Civilian Agencies", "State Government IT"],
      domains: [".gov", ".mil", "defense contractors"],
      accessMethods: ["CVE-2024-24919 (Check Point)", "CVE-2024-3400 (Palo Alto)", "CVE-2019-19781 (Citrix)"],
      priceRange: { min: 5000, max: 50000, currency: "USD" },
    },
    linkedGroups: ["ALPHV/BlackCat", "NoEscape", "Ransomhouse"],
    mitreTechniques: ["T1190", "T1133", "T1078", "T1021.001", "T1059.001"],
    cisaAdvisories: ["AA24-241A"],
    riskScore: 98,
    lastActive: "2025-03",
    notes: "Iranian state-sponsored actor moonlighting as IAB. Sells VPN/RDP access to US government networks. CISA/FBI joint advisory confirms active targeting of federal agencies.",
  },
  {
    brokerId: "iab-exotic-lily",
    brokerName: "Exotic Lily",
    aliases: ["DEV-0950"],
    attribution: "Eastern Europe (suspected)",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums", "Exploit"],
    accessTypes: ["email_access", "domain_admin"],
    govTargeting: {
      agencies: ["Federal Civilian Agencies", "Healthcare (HHS)", "Education (ED)"],
      domains: [".gov", "government contractors"],
      accessMethods: ["Spear-phishing with ISO/LNK payloads", "BumbleBee loader", "MHTML exploit"],
      priceRange: { min: 3000, max: 25000, currency: "USD" },
    },
    linkedGroups: ["Conti", "Diavol", "BumbleBee"],
    mitreTechniques: ["T1566.001", "T1204.002", "T1059.001", "T1547.001"],
    cisaAdvisories: [],
    riskScore: 88,
    lastActive: "2025-02",
    notes: "High-volume phishing IAB tracked by Google TAG. Uses fake business personas to deliver BumbleBee payloads to government employees.",
  },
  {
    brokerId: "iab-scattered-spider",
    brokerName: "Scattered Spider",
    aliases: ["UNC3944", "Roasted 0ktapus", "Starfraud", "Muddled Libra"],
    attribution: "US/UK (English-speaking)",
    sponsorship: "cybercrime",
    primaryForums: ["Telegram", "BreachForums", "Discord"],
    accessTypes: ["cloud_access", "email_access", "domain_admin"],
    govTargeting: {
      agencies: ["Federal Civilian Agencies", "Telecommunications (FCC regulated)", "Financial Regulators"],
      domains: [".gov", "government cloud tenants"],
      accessMethods: ["SIM swapping", "Social engineering helpdesks", "Okta/Azure AD credential theft", "MFA fatigue"],
      priceRange: { min: 10000, max: 100000, currency: "USD" },
    },
    linkedGroups: ["ALPHV/BlackCat", "Qilin"],
    mitreTechniques: ["T1566.004", "T1078.004", "T1556.006", "T1621", "T1199"],
    cisaAdvisories: ["AA23-320A"],
    riskScore: 95,
    lastActive: "2025-04",
    notes: "Young English-speaking group using social engineering + stolen credentials to access government cloud environments. Known for SIM swapping government employees.",
  },
  {
    brokerId: "iab-medusa-affiliates",
    brokerName: "Medusa IAB Network",
    aliases: ["Medusa Locker Affiliates"],
    attribution: "Multi-national",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums", "RAMP", "Exploit"],
    accessTypes: ["rdp_access", "vpn_access", "webshell"],
    govTargeting: {
      agencies: ["State/Local Government", "School Districts", "Water Utilities", "Healthcare"],
      domains: [".gov", "state.*.us", "county government"],
      accessMethods: ["RDP brute force", "Phishing", "Exploiting unpatched VPNs"],
      priceRange: { min: 1000, max: 15000, currency: "USD" },
    },
    linkedGroups: ["Medusa Ransomware"],
    mitreTechniques: ["T1133", "T1021.001", "T1110.001", "T1566.001"],
    cisaAdvisories: ["AA25-071A"],
    riskScore: 90,
    lastActive: "2025-03",
    notes: "CISA advisory confirms Medusa recruits IABs in cybercriminal forums to obtain initial access to government networks. Over 300 victims across critical infrastructure.",
  },
  {
    brokerId: "iab-darkforums-gov-seller",
    brokerName: "GovAccess_Seller",
    aliases: ["gov_rdp_shop", "fedaccess"],
    attribution: "Unknown (Russian-speaking)",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums"],
    accessTypes: ["rdp_access", "domain_admin", "vpn_access"],
    govTargeting: {
      agencies: ["Federal Civilian Agencies", "State Government", "Municipal Government"],
      domains: [".gov", ".us"],
      accessMethods: ["Infostealer harvested credentials", "RDP with Domain Admin"],
      priceRange: { min: 5000, max: 75000, currency: "USD" },
    },
    linkedGroups: [],
    mitreTechniques: ["T1078", "T1021.001", "T1552.001"],
    cisaAdvisories: [],
    riskScore: 85,
    lastActive: "2025-04",
    notes: "Prolific seller on DarkForums specializing in US government admin panel access. Rapid7 H2 2025 data shows DarkForums as principal platform for government access sales.",
  },
  {
    brokerId: "iab-ramp-gov-broker",
    brokerName: "RAMP Gov Broker",
    aliases: ["us_fed_access", "ramp_gov"],
    attribution: "Unknown (Russian-speaking)",
    sponsorship: "cybercrime",
    primaryForums: ["RAMP"],
    accessTypes: ["vpn_access", "citrix_access", "cloud_access"],
    govTargeting: {
      agencies: ["Defense Industrial Base", "Federal Civilian Agencies", "Intelligence Community Contractors"],
      domains: [".gov", ".mil", "defense contractors"],
      accessMethods: ["Stolen VPN credentials", "Citrix Gateway exploits", "AWS/Azure gov cloud tokens"],
      priceRange: { min: 10000, max: 150000, currency: "USD" },
    },
    linkedGroups: ["LockBit", "BlackBasta"],
    mitreTechniques: ["T1133", "T1190", "T1078.004"],
    cisaAdvisories: [],
    riskScore: 92,
    lastActive: "2025-03",
    notes: "RAMP forum broker with 208 threads in H2 2025. Specializes in high-value government VPN and cloud access. Known to supply LockBit and BlackBasta affiliates.",
  },
  {
    brokerId: "iab-gov-email-shop",
    brokerName: "GovMail Shop",
    aliases: ["fed_email_seller", "dotgov_shop"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["Telegram", "BreachForums"],
    accessTypes: ["email_access"],
    govTargeting: {
      agencies: ["FBI", "DOJ", "State Police", "Local Law Enforcement", "Federal Courts"],
      domains: [".gov", ".fbi.gov", "police departments"],
      accessMethods: ["Infostealer malware (Raccoon, RedLine, Vidar)", "Credential stuffing"],
      priceRange: { min: 40, max: 500, currency: "USD" },
    },
    linkedGroups: [],
    mitreTechniques: ["T1078", "T1552.001", "T1114.002"],
    cisaAdvisories: [],
    riskScore: 80,
    lastActive: "2025-04",
    notes: "Sells active .gov and law enforcement email accounts for as little as $40. Accounts include access to law enforcement dashboards, license plate lookups, and investigative portals. Used for fake subpoenas and emergency data requests.",
  },
  {
    brokerId: "iab-xss-gov-specialist",
    brokerName: "XSS Gov Specialist",
    aliases: ["xss_fed_access"],
    attribution: "Unknown (Russian-speaking)",
    sponsorship: "cybercrime",
    primaryForums: ["XSS"],
    accessTypes: ["webshell", "database_access", "domain_admin"],
    govTargeting: {
      agencies: ["State Government Web Portals", "Municipal Services", "Government Databases"],
      domains: [".gov", "state portals"],
      accessMethods: ["SQL injection", "Web application exploits", "CMS vulnerabilities"],
      priceRange: { min: 2000, max: 20000, currency: "USD" },
    },
    linkedGroups: [],
    mitreTechniques: ["T1190", "T1505.003", "T1059.004"],
    cisaAdvisories: [],
    riskScore: 75,
    lastActive: "2025-01",
    notes: "XSS forum specialist selling webshell and database access to state government portals. Lower volume but persistent activity.",
  },
  {
    brokerId: "iab-breachforums-gov",
    brokerName: "BreachForums Gov Dealer",
    aliases: ["bf_gov_creds", "usgov_dumps"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["BreachForums"],
    accessTypes: ["credential_dump", "email_access", "vpn_access"],
    govTargeting: {
      agencies: ["Multiple Federal Agencies", "State Government", "Military Contractors"],
      domains: [".gov", ".mil", "government contractors"],
      accessMethods: ["Credential dumps from infostealers", "Combo lists with .gov emails", "VPN credential leaks"],
      priceRange: { min: 100, max: 5000, currency: "USD" },
    },
    linkedGroups: [],
    mitreTechniques: ["T1078", "T1552.001", "T1589.001"],
    cisaAdvisories: [],
    riskScore: 78,
    lastActive: "2025-04",
    notes: "High-volume credential dump seller on BreachForums. Regularly posts .gov and .mil credential compilations. 30 threads in H2 2025.",
  },
  {
    brokerId: "iab-exploit-forum-gov",
    brokerName: "Exploit Forum Gov Broker",
    aliases: ["exploit_gov_access"],
    attribution: "Unknown (Russian-speaking)",
    sponsorship: "cybercrime",
    primaryForums: ["Exploit"],
    accessTypes: ["vpn_access", "rdp_access", "zero_day"],
    govTargeting: {
      agencies: ["Defense Industrial Base", "Energy Sector (DOE)", "Transportation (DOT)"],
      domains: [".gov", "critical infrastructure"],
      accessMethods: ["Zero-day exploits", "N-day exploitation", "Supply chain compromise"],
      priceRange: { min: 20000, max: 500000, currency: "USD" },
    },
    linkedGroups: ["Cl0p", "LockBit"],
    mitreTechniques: ["T1190", "T1195.002", "T1068"],
    cisaAdvisories: [],
    riskScore: 93,
    lastActive: "2025-02",
    notes: "Premium broker on Exploit forum selling high-value zero-day and n-day access to critical infrastructure including government. 53 threads in H2 2025. Supplies top-tier ransomware groups.",
  },
  {
    brokerId: "iab-telegram-gov-creds",
    brokerName: "Telegram Gov Credential Shops",
    aliases: ["gov_cred_market", "fed_login_shop", "dotgov_access"],
    attribution: "Distributed (multiple operators)",
    sponsorship: "cybercrime",
    primaryForums: ["Telegram", "Signal"],
    accessTypes: ["email_access", "credential_dump"],
    govTargeting: {
      agencies: ["FBI", "DHS", "DOD", "State Police", "Local PD", "Federal Courts", "IRS"],
      domains: [".gov", ".mil", ".fbi.gov", ".dhs.gov", ".irs.gov"],
      accessMethods: ["Infostealer logs (Raccoon, RedLine, Vidar, LummaC2)", "Credential stuffing", "Session token theft"],
      priceRange: { min: 40, max: 2000, currency: "USD" },
    },
    linkedGroups: ["Scattered Spider"],
    mitreTechniques: ["T1078", "T1552.001", "T1539", "T1114.002"],
    cisaAdvisories: [],
    riskScore: 82,
    lastActive: "2025-04",
    notes: "Network of Telegram channels selling .gov credentials harvested by infostealers. FBI.gov addresses bundled with personal details. Used for fake emergency data requests to tech companies.",
  },
  {
    brokerId: "iab-cloud-gov-broker",
    brokerName: "Cloud Gov Broker",
    aliases: ["aws_gov_access", "azure_fed_broker"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums", "RAMP"],
    accessTypes: ["cloud_access"],
    govTargeting: {
      agencies: ["Federal Cloud Tenants (FedRAMP)", "GovCloud Environments", "State Cloud Migration Projects"],
      domains: ["AWS GovCloud", "Azure Government", "Google Cloud Government"],
      accessMethods: ["Stolen IAM credentials", "Compromised service accounts", "Misconfigured S3/Blob storage"],
      priceRange: { min: 15000, max: 200000, currency: "USD" },
    },
    linkedGroups: ["ALPHV/BlackCat"],
    mitreTechniques: ["T1078.004", "T1530", "T1580"],
    cisaAdvisories: [],
    riskScore: 94,
    lastActive: "2025-03",
    notes: "Emerging broker specializing in government cloud access. FedRAMP and GovCloud environments command premium prices. Growing threat as agencies migrate to cloud.",
  },
  {
    brokerId: "iab-sltt-broker",
    brokerName: "SLTT Access Broker",
    aliases: ["city_gov_access", "county_rdp"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums", "BreachForums"],
    accessTypes: ["rdp_access", "vpn_access", "webshell"],
    govTargeting: {
      agencies: ["City Government", "County Government", "School Districts", "Water/Sewer Utilities", "911 Centers"],
      domains: ["city.*.gov", "county.*.gov", "state.*.us"],
      accessMethods: ["RDP brute force", "Unpatched VPN appliances", "Default credentials"],
      priceRange: { min: 500, max: 5000, currency: "USD" },
    },
    linkedGroups: ["Royal/BlackSuit", "Akira", "Play"],
    mitreTechniques: ["T1133", "T1021.001", "T1110.001", "T1078.001"],
    cisaAdvisories: [],
    riskScore: 72,
    lastActive: "2025-04",
    notes: "Volume broker targeting underfunded state/local/tribal/territorial (SLTT) government entities. Lower prices reflect weaker security posture. Supplies mid-tier ransomware groups.",
  },
  {
    brokerId: "iab-mil-contractor-broker",
    brokerName: "Military Contractor Broker",
    aliases: ["dib_access", "mil_vpn_seller"],
    attribution: "Unknown (suspected China-nexus)",
    sponsorship: "hybrid",
    primaryForums: ["Exploit", "XSS"],
    accessTypes: ["vpn_access", "domain_admin", "cloud_access"],
    govTargeting: {
      agencies: ["Defense Industrial Base", "Military Contractors", "DARPA Subcontractors", "Intelligence Community Contractors"],
      domains: [".mil contractors", "defense firms", "cleared facilities"],
      accessMethods: ["Supply chain compromise", "Spear-phishing cleared personnel", "VPN credential theft"],
      priceRange: { min: 50000, max: 500000, currency: "USD" },
    },
    linkedGroups: ["APT41", "Volt Typhoon"],
    mitreTechniques: ["T1195.002", "T1566.001", "T1133", "T1078"],
    cisaAdvisories: ["AA23-144A"],
    riskScore: 97,
    lastActive: "2025-03",
    notes: "High-value broker targeting defense industrial base. Suspected state-sponsored overlap with Chinese APT activity. Access to cleared defense contractor networks commands highest prices.",
  },
  {
    brokerId: "iab-healthcare-gov-broker",
    brokerName: "Healthcare Gov Broker",
    aliases: ["hhs_access", "medicare_broker"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["DarkForums", "RAMP"],
    accessTypes: ["vpn_access", "database_access", "email_access"],
    govTargeting: {
      agencies: ["HHS", "CMS (Medicare/Medicaid)", "VA Healthcare", "State Health Departments", "Public Hospitals"],
      domains: [".gov health portals", "state health exchanges"],
      accessMethods: ["Exploiting healthcare VPNs", "Credential theft from health portals", "EHR system access"],
      priceRange: { min: 5000, max: 50000, currency: "USD" },
    },
    linkedGroups: ["BlackCat/ALPHV", "Rhysida"],
    mitreTechniques: ["T1133", "T1078", "T1190", "T1530"],
    cisaAdvisories: [],
    riskScore: 88,
    lastActive: "2025-04",
    notes: "Broker specializing in government healthcare access. VA and HHS systems are high-value targets due to PII/PHI data. Change Healthcare breach demonstrated catastrophic impact potential.",
  },
];

// ─── Government Domain & Agency Patterns ─────────────────────────────────

const GOV_DOMAIN_PATTERNS = [
  /\.gov$/i, /\.mil$/i, /\.fed\.us$/i,
  /\.state\.\w+\.us$/i, /\.county\.\w+/i,
  /\.fbi\.gov/i, /\.dhs\.gov/i, /\.doj\.gov/i,
  /\.irs\.gov/i, /\.ssa\.gov/i, /\.va\.gov/i,
  /\.dod\.mil/i, /\.army\.mil/i, /\.navy\.mil/i,
  /\.af\.mil/i, /\.usmc\.mil/i,
];

const GOV_SECTOR_KEYWORDS = [
  "government", "federal", "state government", "local government",
  "municipal", "military", "defense", "law enforcement", "police",
  "judiciary", "courts", "public sector", "civic", "tribal",
  "intelligence", "homeland security", "national security",
];

const GOV_AGENCY_KEYWORDS = [
  "FBI", "CIA", "NSA", "DHS", "DOD", "DOJ", "DOE", "DOT", "HHS",
  "VA", "IRS", "EPA", "FEMA", "CISA", "SEC", "FTC", "FCC",
  "NASA", "USDA", "HUD", "SBA", "OPM", "GSA", "NIST",
  "State Department", "Treasury", "Pentagon", "White House",
];

// ─── Detection & Scoring ─────────────────────────────────────────────────

export interface GovBrokerListing {
  id: string;
  brokerName: string;
  brokerProfile: GovIabProfile | null;
  listingType: string;
  accessType: string;
  targetAgency: string;
  targetDomain: string;
  accessLevel: string;
  askingPrice: string;
  forumSource: string;
  detectedAt: string;
  govConfidence: number; // 0-100: how confident this targets US gov
  riskScore: number; // 0-100: overall risk
  riskFactors: string[];
  mitreTechniques: string[];
  linkedGroups: string[];
  status: string;
  description: string;
  rawData?: any;
}

/**
 * Detect whether an access broker listing targets US government.
 * Returns a confidence score 0-100.
 */
export function detectGovTargeting(listing: {
  victimSector?: string | null;
  victimCountry?: string | null;
  description?: string | null;
  accessType?: string | null;
  brokerName?: string | null;
  forumPostUrl?: string | null;
}): { isGov: boolean; confidence: number; matchedPatterns: string[] } {
  const patterns: string[] = [];
  let score = 0;

  const desc = (listing.description || "").toLowerCase();
  const sector = (listing.victimSector || "").toLowerCase();
  const country = (listing.victimCountry || "").toLowerCase();

  // Check sector keywords
  for (const kw of GOV_SECTOR_KEYWORDS) {
    if (sector.includes(kw.toLowerCase()) || desc.includes(kw.toLowerCase())) {
      score += 25;
      patterns.push(`sector:${kw}`);
      break;
    }
  }

  // Check agency keywords
  for (const kw of GOV_AGENCY_KEYWORDS) {
    if (desc.includes(kw.toLowerCase()) || desc.includes(kw)) {
      score += 30;
      patterns.push(`agency:${kw}`);
      break;
    }
  }

  // Check domain patterns
  for (const pat of GOV_DOMAIN_PATTERNS) {
    if (pat.test(desc) || pat.test(listing.forumPostUrl || "")) {
      score += 35;
      patterns.push(`domain:${pat.source}`);
      break;
    }
  }

  // Country check (US)
  if (country.includes("us") || country.includes("united states") || country.includes("america")) {
    score += 10;
    patterns.push("country:US");
  }

  // Known gov broker name match
  const knownBroker = GOV_IAB_KNOWLEDGE_BASE.find(
    (b) => b.brokerName.toLowerCase() === (listing.brokerName || "").toLowerCase()
      || b.aliases.some((a) => a.toLowerCase() === (listing.brokerName || "").toLowerCase())
  );
  if (knownBroker) {
    score += 40;
    patterns.push(`known_broker:${knownBroker.brokerName}`);
  }

  return {
    isGov: score >= 25,
    confidence: Math.min(100, score),
    matchedPatterns: patterns,
  };
}

/**
 * Calculate risk score for a government-targeting IAB listing.
 * Government listings receive a severity multiplier.
 */
export function calculateGovRiskScore(listing: {
  accessLevel?: string | null;
  accessType?: string | null;
  askingPrice?: string | null;
  brokerReputation?: string | null;
  linkedRansomwareGroups?: string[] | null;
  govConfidence: number;
}): { score: number; factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  // Base: gov confidence contributes
  score += listing.govConfidence * 0.3;

  // Access level severity
  const level = (listing.accessLevel || "").toLowerCase();
  if (level.includes("domain_admin") || level.includes("domain admin")) {
    score += 25; factors.push("Domain Admin access");
  } else if (level.includes("local_admin") || level.includes("local admin")) {
    score += 18; factors.push("Local Admin access");
  } else if (level.includes("service_account") || level.includes("service account")) {
    score += 15; factors.push("Service Account access");
  } else {
    score += 8;
  }

  // Access type severity
  const atype = (listing.accessType || "").toLowerCase();
  if (atype.includes("cloud")) { score += 15; factors.push("Cloud access (GovCloud/FedRAMP risk)"); }
  if (atype.includes("vpn")) { score += 12; factors.push("VPN access (network-wide risk)"); }
  if (atype.includes("rdp")) { score += 10; factors.push("RDP access"); }
  if (atype.includes("domain_admin")) { score += 15; factors.push("Domain Admin listing"); }
  if (atype.includes("zero_day")) { score += 20; factors.push("Zero-day exploit"); }

  // Price indicates value
  const price = parseFloat((listing.askingPrice || "0").replace(/[^0-9.]/g, ""));
  if (price > 100000) { score += 15; factors.push(`Premium price ($${price.toLocaleString()})`); }
  else if (price > 50000) { score += 10; factors.push(`High price ($${price.toLocaleString()})`); }
  else if (price > 10000) { score += 5; factors.push(`Moderate price ($${price.toLocaleString()})`); }

  // Broker reputation
  if (listing.brokerReputation === "established") { score += 10; factors.push("Established broker"); }
  else if (listing.brokerReputation === "rising") { score += 5; factors.push("Rising broker"); }

  // Linked ransomware groups
  if (listing.linkedRansomwareGroups && listing.linkedRansomwareGroups.length > 0) {
    score += 10; factors.push(`Linked to ${listing.linkedRansomwareGroups.join(", ")}`);
  }

  // Government severity multiplier (1.3x)
  score = Math.round(score * 1.3);

  return { score: Math.min(100, score), factors };
}

// ─── Forum Activity Patterns ─────────────────────────────────────────────

export interface ForumActivityPattern {
  forum: string;
  govListings: number;
  avgPrice: number;
  topAccessTypes: string[];
  riskLevel: "critical" | "high" | "medium" | "low";
  description: string;
}

/**
 * Get forum activity patterns for government access sales.
 * Based on Rapid7 H2 2025 data.
 */
export function getForumActivityPatterns(): ForumActivityPattern[] {
  return [
    {
      forum: "DarkForums",
      govListings: 221,
      avgPrice: 113275,
      topAccessTypes: ["Admin Panel", "RDP", "VPN"],
      riskLevel: "critical",
      description: "Principal platform for government access sales. 221 threads in H2 2025. Admin panel access is the most commonly offered type for government sector.",
    },
    {
      forum: "RAMP",
      govListings: 208,
      avgPrice: 85000,
      topAccessTypes: ["VPN", "Citrix", "Cloud"],
      riskLevel: "critical",
      description: "Second most active forum. 208 threads in H2 2025. Specializes in high-value VPN and cloud access to government networks. Known supplier to LockBit and BlackBasta.",
    },
    {
      forum: "Exploit",
      govListings: 53,
      avgPrice: 250000,
      topAccessTypes: ["Zero-day", "VPN", "Supply Chain"],
      riskLevel: "high",
      description: "Premium Russian-language forum. 53 threads in H2 2025. Highest average prices due to zero-day and supply chain access offerings.",
    },
    {
      forum: "BreachForums",
      govListings: 30,
      avgPrice: 2500,
      topAccessTypes: ["Credential Dumps", "Email Access", "Database Leaks"],
      riskLevel: "high",
      description: "Data leak marketplace. 30 threads in H2 2025. Lower prices but high volume of .gov credential compilations.",
    },
    {
      forum: "XSS",
      govListings: 18,
      avgPrice: 15000,
      topAccessTypes: ["Webshell", "Database", "CMS"],
      riskLevel: "medium",
      description: "Declining but persistent. 18 threads in H2 2025. Specializes in web application access to state government portals.",
    },
    {
      forum: "Telegram/Signal",
      govListings: 50,
      avgPrice: 500,
      topAccessTypes: ["Email Access", "Credentials", "Session Tokens"],
      riskLevel: "high",
      description: "Growing marketplace for low-cost .gov email accounts ($40-$500). Infostealer-harvested credentials sold via encrypted messaging. Used for fake subpoenas.",
    },
  ];
}

// ─── Statistics & Aggregation ────────────────────────────────────────────

export interface GovBrokerStats {
  totalKnownBrokers: number;
  activeBrokers: number;
  totalForumListings: number;
  avgAskingPrice: number;
  topAccessTypes: { type: string; count: number }[];
  topTargetedAgencies: { agency: string; count: number }[];
  topForums: { forum: string; listings: number }[];
  riskDistribution: { level: string; count: number }[];
  priceRange: { min: number; max: number; avg: number };
  recentActivity: { period: string; newListings: number; priceTrend: string }[];
}

/**
 * Generate aggregate statistics from the knowledge base.
 */
export function getGovBrokerStats(): GovBrokerStats {
  const brokers = GOV_IAB_KNOWLEDGE_BASE;
  const forums = getForumActivityPatterns();

  // Access type frequency
  const accessTypeCounts = new Map<string, number>();
  for (const b of brokers) {
    for (const at of b.accessTypes) {
      accessTypeCounts.set(at, (accessTypeCounts.get(at) || 0) + 1);
    }
  }
  const topAccessTypes = [...accessTypeCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([type, count]) => ({ type: type.replace(/_/g, " "), count }));

  // Targeted agencies
  const agencyCounts = new Map<string, number>();
  for (const b of brokers) {
    for (const a of b.govTargeting.agencies) {
      agencyCounts.set(a, (agencyCounts.get(a) || 0) + 1);
    }
  }
  const topTargetedAgencies = [...agencyCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([agency, count]) => ({ agency, count }));

  // Price analysis
  const prices = brokers.flatMap((b) => [b.govTargeting.priceRange.min, b.govTargeting.priceRange.max]);
  const minPrice = Math.min(...prices);
  const maxPrice = Math.max(...prices);
  const avgPrice = Math.round(prices.reduce((s, p) => s + p, 0) / prices.length);

  // Risk distribution
  const riskDist = [
    { level: "Critical (90-100)", count: brokers.filter((b) => b.riskScore >= 90).length },
    { level: "High (75-89)", count: brokers.filter((b) => b.riskScore >= 75 && b.riskScore < 90).length },
    { level: "Medium (50-74)", count: brokers.filter((b) => b.riskScore >= 50 && b.riskScore < 75).length },
    { level: "Low (<50)", count: brokers.filter((b) => b.riskScore < 50).length },
  ];

  return {
    totalKnownBrokers: brokers.length,
    activeBrokers: brokers.filter((b) => {
      const d = new Date(b.lastActive);
      return (Date.now() - d.getTime()) < 90 * 24 * 60 * 60 * 1000;
    }).length,
    totalForumListings: forums.reduce((s, f) => s + f.govListings, 0),
    avgAskingPrice: avgPrice,
    topAccessTypes,
    topTargetedAgencies,
    topForums: forums.map((f) => ({ forum: f.forum, listings: f.govListings })),
    riskDistribution: riskDist,
    priceRange: { min: minPrice, max: maxPrice, avg: avgPrice },
    recentActivity: [
      { period: "H2 2025", newListings: 580, priceTrend: "up_4055%" },
      { period: "H1 2025", newListings: 320, priceTrend: "up_200%" },
      { period: "H2 2024", newListings: 180, priceTrend: "stable" },
    ],
  };
}

/**
 * Enrich an existing access broker listing with government targeting intelligence.
 */
export function enrichWithGovIntel(listing: {
  brokerId?: string;
  brokerName?: string;
  victimSector?: string | null;
  victimCountry?: string | null;
  description?: string | null;
  accessType?: string | null;
  accessLevel?: string | null;
  askingPrice?: string | null;
  brokerReputation?: string | null;
  linkedRansomwareGroups?: string[] | null;
  forumPostUrl?: string | null;
}): {
  isGovTarget: boolean;
  govConfidence: number;
  riskScore: number;
  riskFactors: string[];
  matchedPatterns: string[];
  knownProfile: GovIabProfile | null;
} {
  const detection = detectGovTargeting(listing);
  if (!detection.isGov) {
    return {
      isGovTarget: false,
      govConfidence: 0,
      riskScore: 0,
      riskFactors: [],
      matchedPatterns: [],
      knownProfile: null,
    };
  }

  const risk = calculateGovRiskScore({
    ...listing,
    govConfidence: detection.confidence,
  });

  const knownProfile = GOV_IAB_KNOWLEDGE_BASE.find(
    (b) => b.brokerName.toLowerCase() === (listing.brokerName || "").toLowerCase()
      || b.aliases.some((a) => a.toLowerCase() === (listing.brokerName || "").toLowerCase())
      || b.brokerId === listing.brokerId
  ) || null;

  return {
    isGovTarget: true,
    govConfidence: detection.confidence,
    riskScore: risk.score,
    riskFactors: risk.factors,
    matchedPatterns: detection.matchedPatterns,
    knownProfile,
  };
}

/**
 * Get all known government IAB profiles sorted by risk score.
 */
export function getKnownGovBrokers(): GovIabProfile[] {
  return [...GOV_IAB_KNOWLEDGE_BASE].sort((a, b) => b.riskScore - a.riskScore);
}

/**
 * Search the knowledge base by keyword.
 */
export function searchGovBrokers(query: string): GovIabProfile[] {
  const q = query.toLowerCase();
  return GOV_IAB_KNOWLEDGE_BASE.filter((b) =>
    b.brokerName.toLowerCase().includes(q)
    || b.aliases.some((a) => a.toLowerCase().includes(q))
    || b.notes.toLowerCase().includes(q)
    || b.govTargeting.agencies.some((a) => a.toLowerCase().includes(q))
    || b.linkedGroups.some((g) => g.toLowerCase().includes(q))
    || b.attribution.toLowerCase().includes(q)
  );
}
