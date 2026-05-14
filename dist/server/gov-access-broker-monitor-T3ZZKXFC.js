import "./chunk-KFQGP6VL.js";

// server/lib/gov-access-broker-monitor.ts
var GOV_IAB_KNOWLEDGE_BASE = [
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
      priceRange: { min: 5e3, max: 5e4, currency: "USD" }
    },
    linkedGroups: ["ALPHV/BlackCat", "NoEscape", "Ransomhouse"],
    mitreTechniques: ["T1190", "T1133", "T1078", "T1021.001", "T1059.001"],
    cisaAdvisories: ["AA24-241A"],
    riskScore: 98,
    lastActive: "2025-03",
    notes: "Iranian state-sponsored actor moonlighting as IAB. Sells VPN/RDP access to US government networks. CISA/FBI joint advisory confirms active targeting of federal agencies."
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
      priceRange: { min: 3e3, max: 25e3, currency: "USD" }
    },
    linkedGroups: ["Conti", "Diavol", "BumbleBee"],
    mitreTechniques: ["T1566.001", "T1204.002", "T1059.001", "T1547.001"],
    cisaAdvisories: [],
    riskScore: 88,
    lastActive: "2025-02",
    notes: "High-volume phishing IAB tracked by Google TAG. Uses fake business personas to deliver BumbleBee payloads to government employees."
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
      priceRange: { min: 1e4, max: 1e5, currency: "USD" }
    },
    linkedGroups: ["ALPHV/BlackCat", "Qilin"],
    mitreTechniques: ["T1566.004", "T1078.004", "T1556.006", "T1621", "T1199"],
    cisaAdvisories: ["AA23-320A"],
    riskScore: 95,
    lastActive: "2025-04",
    notes: "Young English-speaking group using social engineering + stolen credentials to access government cloud environments. Known for SIM swapping government employees."
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
      priceRange: { min: 1e3, max: 15e3, currency: "USD" }
    },
    linkedGroups: ["Medusa Ransomware"],
    mitreTechniques: ["T1133", "T1021.001", "T1110.001", "T1566.001"],
    cisaAdvisories: ["AA25-071A"],
    riskScore: 90,
    lastActive: "2025-03",
    notes: "CISA advisory confirms Medusa recruits IABs in cybercriminal forums to obtain initial access to government networks. Over 300 victims across critical infrastructure."
  },
  {
    brokerId: "iab-intelbroker",
    brokerName: "IntelBroker",
    aliases: ["Kai Logan West", "ChinaFarmer"],
    attribution: "UK (British national)",
    sponsorship: "cybercrime",
    primaryForums: ["BreachForums"],
    accessTypes: ["credential_dump", "domain_admin", "email_access"],
    govTargeting: {
      agencies: ["DC Health Link (US Congress PII)", "US Customs and Border Protection", "Europol", "DARPA", "ICE"],
      domains: [".gov", "europol.europa.eu"],
      accessMethods: ["Third-party vendor compromise", "Credential harvesting", "Admin panel exploitation"],
      priceRange: { min: 0, max: 5e4, currency: "USD" }
    },
    linkedGroups: ["BreachForums Administration"],
    mitreTechniques: ["T1078", "T1552.001", "T1114.002", "T1530"],
    cisaAdvisories: [],
    riskScore: 96,
    lastActive: "2025-06",
    notes: "Kai Logan West charged Jun 2025 by DOJ SDNY for $25M+ in damages. Breached DC Health Link exposing PII of US Congress members. Served as BreachForums administrator. Also breached Europol EPE, AMD, claimed Apple source code."
  },
  {
    brokerId: "iab-inthematrix1",
    brokerName: "InTheMatrix1",
    aliases: ["Catalin Dragomir"],
    attribution: "Romania",
    sponsorship: "cybercrime",
    primaryForums: ["Exploit", "XSS"],
    accessTypes: ["rdp_access", "vpn_access"],
    govTargeting: {
      agencies: ["Oregon State Government", "US Corporate Networks"],
      domains: [".gov", "state government offices"],
      accessMethods: ["RDP brute force", "Credential theft", "Network access resale"],
      priceRange: { min: 2500, max: 5e3, currency: "USD" }
    },
    linkedGroups: ["Ransomware affiliates (unnamed)"],
    mitreTechniques: ["T1021.001", "T1078", "T1133"],
    cisaAdvisories: [],
    riskScore: 85,
    lastActive: "2024-11",
    notes: "Romanian national pleaded guilty Feb 2026 to selling RDP access to Oregon state government for $3,000 BTC. Arrested Romania Nov 2024, extradited Jan 2025. Caused $250K+ in losses. DOJ District of Oregon."
  },
  {
    brokerId: "iab-kiberphant0m",
    brokerName: "Kiberphant0m",
    aliases: ["Cameron John Wagenius"],
    attribution: "US (US Army soldier)",
    sponsorship: "cybercrime",
    primaryForums: ["BreachForums"],
    accessTypes: ["cloud_access", "database_access"],
    govTargeting: {
      agencies: ["AT&T (telecom infrastructure)", "T-Mobile", "Snowflake cloud customers"],
      domains: ["telecom infrastructure", "cloud platforms"],
      accessMethods: ["Snowflake cloud platform exploitation", "Credential theft", "Extortion"],
      priceRange: { min: 5e5, max: 1e6, currency: "USD" }
    },
    linkedGroups: ["UNC5537"],
    mitreTechniques: ["T1078.004", "T1530", "T1567"],
    cisaAdvisories: [],
    riskScore: 90,
    lastActive: "2025-07",
    notes: "21-year-old US Army soldier pleaded guilty Jul 2025. Hacked telecom companies via Snowflake cloud platform. Attempted to extort AT&T for $1M after stealing call records of 109M customers. Connected to Mandiant-tracked UNC5537."
  },
  {
    brokerId: "iab-wazawaka",
    brokerName: "Wazawaka",
    aliases: ["Mikhail Matveev", "Boriselcin", "m1x", "Orange"],
    attribution: "Russia",
    sponsorship: "cybercrime",
    primaryForums: ["RAMP", "Exploit"],
    accessTypes: ["vpn_access", "rdp_access", "domain_admin"],
    govTargeting: {
      agencies: ["DC Metropolitan Police", "US Hospitals", "US Schools"],
      domains: [".gov", "law enforcement networks"],
      accessMethods: ["VPN exploitation", "RDP access resale", "Ransomware deployment (Babuk, Hive, LockBit)"],
      priceRange: { min: 5e3, max: 5e4, currency: "USD" }
    },
    linkedGroups: ["Babuk", "Hive", "LockBit"],
    mitreTechniques: ["T1133", "T1021.001", "T1486", "T1078"],
    cisaAdvisories: [],
    riskScore: 94,
    lastActive: "2024-12",
    notes: "Russian national indicted by US DOJ. Deployed Babuk ransomware against DC Metropolitan Police Apr 2021. FBI $10M reward. Charged by Russia Dec 2024. Operated as both IAB and ransomware affiliate."
  },
  {
    brokerId: "iab-mora001",
    brokerName: "Mora_001",
    aliases: [],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["Unknown"],
    accessTypes: ["vpn_access", "exploit_kit"],
    govTargeting: {
      agencies: ["Multiple sectors including government"],
      domains: ["FortiGate firewall customers"],
      accessMethods: ["CVE-2024-46720 (Fortinet)", "CVE-2024-55591 (Fortinet)", "FortiGate firewall exploitation"],
      priceRange: { min: 1e4, max: 5e4, currency: "USD" }
    },
    linkedGroups: ["Medusa Ransomware", "LockBit (builder)"],
    mitreTechniques: ["T1190", "T1133", "T1486"],
    cisaAdvisories: [],
    riskScore: 88,
    lastActive: "2025-03",
    notes: "Documented by Forescout Mar 2025. Exploits Fortinet FortiGate firewall vulnerabilities. Deploys SuperBlack ransomware (modified LockBit builder). Linked to Medusa ransomware ecosystem."
  },
  {
    brokerId: "iab-storm1175",
    brokerName: "Storm-1175",
    aliases: [],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["Private"],
    accessTypes: ["exploit_kit", "domain_admin"],
    govTargeting: {
      agencies: ["Critical infrastructure including government"],
      domains: ["multiple sectors"],
      accessMethods: ["Zero-day exploitation", "Rapid access-to-ransomware pipeline"],
      priceRange: { min: 25e3, max: 1e5, currency: "USD" }
    },
    linkedGroups: ["Medusa Ransomware"],
    mitreTechniques: ["T1190", "T1068", "T1486"],
    cisaAdvisories: [],
    riskScore: 86,
    lastActive: "2026-04",
    notes: "Microsoft-tracked Medusa ransomware affiliate. Documented Apr 2026 exploiting zero-day vulnerabilities. Moves from initial access to data exfiltration and Medusa deployment within days."
  },
  {
    brokerId: "iab-fin7",
    brokerName: "FIN7",
    aliases: ["Carbanak Group", "Carbon Spider", "Sangria Tempest"],
    attribution: "Russia/Ukraine",
    sponsorship: "cybercrime",
    primaryForums: ["Private"],
    accessTypes: ["domain_admin", "cloud_access"],
    govTargeting: {
      agencies: ["US Retail", "US Hospitality", "US Gaming"],
      domains: ["payment processing systems"],
      accessMethods: ["Spear-phishing", "Carbanak malware", "Supply chain compromise"],
      priceRange: { min: 25e3, max: 1e5, currency: "USD" }
    },
    linkedGroups: ["REvil", "DarkSide", "BlackMatter"],
    mitreTechniques: ["T1566.001", "T1059.001", "T1547.001", "T1078"],
    cisaAdvisories: [],
    riskScore: 92,
    lastActive: "2025-06",
    notes: "Targeted 100+ US companies. FBI documented 15M+ stolen payment cards. Multiple members convicted. Transitioned from financial crime to ransomware affiliate operations with REvil, DarkSide, BlackMatter."
  },
  {
    brokerId: "iab-fin12",
    brokerName: "FIN12",
    aliases: ["Pistol Tempest", "DEV-0237"],
    attribution: "Russia (suspected)",
    sponsorship: "cybercrime",
    primaryForums: ["Private"],
    accessTypes: ["domain_admin", "vpn_access"],
    govTargeting: {
      agencies: ["US Healthcare", "US Government", "Critical Infrastructure"],
      domains: [".gov", "healthcare systems"],
      accessMethods: ["TrickBot/BazarLoader", "Purchasing access from other IABs", "Cobalt Strike"],
      priceRange: { min: 2e4, max: 75e3, currency: "USD" }
    },
    linkedGroups: ["Ryuk", "Conti"],
    mitreTechniques: ["T1059.001", "T1078", "T1486", "T1021.001"],
    cisaAdvisories: [],
    riskScore: 91,
    lastActive: "2025-09",
    notes: "Documented by Mandiant as prolific ransomware deployer purchasing access from IABs. Primarily targets healthcare and government. Deploys Ryuk and Conti within 2-5 days of access."
  },
  {
    brokerId: "iab-play-affiliates",
    brokerName: "Play Ransomware Affiliates",
    aliases: ["PlayCrypt", "Balloonfly"],
    attribution: "Unknown",
    sponsorship: "cybercrime",
    primaryForums: ["Private"],
    accessTypes: ["rdp_access", "vpn_access", "exploit_kit"],
    govTargeting: {
      agencies: ["US Government", "US Healthcare", "US Education"],
      domains: [".gov", "critical infrastructure"],
      accessMethods: ["Stolen credentials from IABs", "FortiOS/ProxyNotShell exploits", "RDP compromise"],
      priceRange: { min: 1e4, max: 5e4, currency: "USD" }
    },
    linkedGroups: ["Play Ransomware"],
    mitreTechniques: ["T1190", "T1078", "T1021.001", "T1486"],
    cisaAdvisories: ["AA23-352A"],
    riskScore: 87,
    lastActive: "2025-06",
    notes: "FBI/CISA Joint Advisory (updated Jun 2025): Play ransomware group uses IABs and stolen credentials for initial access to critical infrastructure. Targets government, healthcare, education."
  },
  {
    brokerId: "iab-blacksuit-affiliates",
    brokerName: "BlackSuit Affiliates",
    aliases: ["Royal", "DEV-0569"],
    attribution: "Russia (suspected)",
    sponsorship: "cybercrime",
    primaryForums: ["Private"],
    accessTypes: ["exploit_kit", "domain_admin", "vpn_access"],
    govTargeting: {
      agencies: ["US Government", "Critical Infrastructure", "Manufacturing"],
      domains: [".gov", "critical infrastructure"],
      accessMethods: ["Callback phishing", "IAB-purchased access", "Public-facing application exploits"],
      priceRange: { min: 15e3, max: 75e3, currency: "USD" }
    },
    linkedGroups: ["BlackSuit/Royal Ransomware"],
    mitreTechniques: ["T1190", "T1566.001", "T1078", "T1486"],
    cisaAdvisories: ["AA23-061A"],
    riskScore: 89,
    lastActive: "2025-08",
    notes: "CISA Advisory AA23-061A (updated Aug 2024): BlackSuit (formerly Royal) uses IABs and exploits public-facing applications. Demanded over $500M in ransoms across critical infrastructure including government."
  }
];
var GOV_DOMAIN_PATTERNS = [
  /\.gov$/i,
  /\.mil$/i,
  /\.fed\.us$/i,
  /\.state\.\w+\.us$/i,
  /\.county\.\w+/i,
  /\.fbi\.gov/i,
  /\.dhs\.gov/i,
  /\.doj\.gov/i,
  /\.irs\.gov/i,
  /\.ssa\.gov/i,
  /\.va\.gov/i,
  /\.dod\.mil/i,
  /\.army\.mil/i,
  /\.navy\.mil/i,
  /\.af\.mil/i,
  /\.usmc\.mil/i
];
var GOV_SECTOR_KEYWORDS = [
  "government",
  "federal",
  "state government",
  "local government",
  "municipal",
  "military",
  "defense",
  "law enforcement",
  "police",
  "judiciary",
  "courts",
  "public sector",
  "civic",
  "tribal",
  "intelligence",
  "homeland security",
  "national security"
];
var GOV_AGENCY_KEYWORDS = [
  "FBI",
  "CIA",
  "NSA",
  "DHS",
  "DOD",
  "DOJ",
  "DOE",
  "DOT",
  "HHS",
  "VA",
  "IRS",
  "EPA",
  "FEMA",
  "CISA",
  "SEC",
  "FTC",
  "FCC",
  "NASA",
  "USDA",
  "HUD",
  "SBA",
  "OPM",
  "GSA",
  "NIST",
  "State Department",
  "Treasury",
  "Pentagon",
  "White House"
];
function detectGovTargeting(listing) {
  const patterns = [];
  let score = 0;
  const desc = (listing.description || "").toLowerCase();
  const sector = (listing.victimSector || "").toLowerCase();
  const country = (listing.victimCountry || "").toLowerCase();
  for (const kw of GOV_SECTOR_KEYWORDS) {
    if (sector.includes(kw.toLowerCase()) || desc.includes(kw.toLowerCase())) {
      score += 25;
      patterns.push(`sector:${kw}`);
      break;
    }
  }
  for (const kw of GOV_AGENCY_KEYWORDS) {
    if (desc.includes(kw.toLowerCase()) || desc.includes(kw)) {
      score += 30;
      patterns.push(`agency:${kw}`);
      break;
    }
  }
  for (const pat of GOV_DOMAIN_PATTERNS) {
    if (pat.test(desc) || pat.test(listing.forumPostUrl || "")) {
      score += 35;
      patterns.push(`domain:${pat.source}`);
      break;
    }
  }
  if (country.includes("us") || country.includes("united states") || country.includes("america")) {
    score += 10;
    patterns.push("country:US");
  }
  const knownBroker = GOV_IAB_KNOWLEDGE_BASE.find(
    (b) => b.brokerName.toLowerCase() === (listing.brokerName || "").toLowerCase() || b.aliases.some((a) => a.toLowerCase() === (listing.brokerName || "").toLowerCase())
  );
  if (knownBroker) {
    score += 40;
    patterns.push(`known_broker:${knownBroker.brokerName}`);
  }
  return {
    isGov: score >= 25,
    confidence: Math.min(100, score),
    matchedPatterns: patterns
  };
}
function calculateGovRiskScore(listing) {
  let score = 0;
  const factors = [];
  score += listing.govConfidence * 0.3;
  const level = (listing.accessLevel || "").toLowerCase();
  if (level.includes("domain_admin") || level.includes("domain admin")) {
    score += 25;
    factors.push("Domain Admin access");
  } else if (level.includes("local_admin") || level.includes("local admin")) {
    score += 18;
    factors.push("Local Admin access");
  } else if (level.includes("service_account") || level.includes("service account")) {
    score += 15;
    factors.push("Service Account access");
  } else {
    score += 8;
  }
  const atype = (listing.accessType || "").toLowerCase();
  if (atype.includes("cloud")) {
    score += 15;
    factors.push("Cloud access (GovCloud/FedRAMP risk)");
  }
  if (atype.includes("vpn")) {
    score += 12;
    factors.push("VPN access (network-wide risk)");
  }
  if (atype.includes("rdp")) {
    score += 10;
    factors.push("RDP access");
  }
  if (atype.includes("domain_admin")) {
    score += 15;
    factors.push("Domain Admin listing");
  }
  if (atype.includes("zero_day")) {
    score += 20;
    factors.push("Zero-day exploit");
  }
  const price = parseFloat((listing.askingPrice || "0").replace(/[^0-9.]/g, ""));
  if (price > 1e5) {
    score += 15;
    factors.push(`Premium price ($${price.toLocaleString()})`);
  } else if (price > 5e4) {
    score += 10;
    factors.push(`High price ($${price.toLocaleString()})`);
  } else if (price > 1e4) {
    score += 5;
    factors.push(`Moderate price ($${price.toLocaleString()})`);
  }
  if (listing.brokerReputation === "established") {
    score += 10;
    factors.push("Established broker");
  } else if (listing.brokerReputation === "rising") {
    score += 5;
    factors.push("Rising broker");
  }
  if (listing.linkedRansomwareGroups && listing.linkedRansomwareGroups.length > 0) {
    score += 10;
    factors.push(`Linked to ${listing.linkedRansomwareGroups.join(", ")}`);
  }
  score = Math.round(score * 1.3);
  return { score: Math.min(100, score), factors };
}
function getForumActivityPatterns() {
  return [
    {
      forum: "DarkForums",
      govListings: 221,
      avgPrice: 113275,
      topAccessTypes: ["Admin Panel", "RDP", "VPN"],
      riskLevel: "critical",
      description: "Principal platform for government access sales. 221 threads in H2 2025. Admin panel access is the most commonly offered type for government sector."
    },
    {
      forum: "RAMP",
      govListings: 208,
      avgPrice: 85e3,
      topAccessTypes: ["VPN", "Citrix", "Cloud"],
      riskLevel: "critical",
      description: "Second most active forum. 208 threads in H2 2025. Specializes in high-value VPN and cloud access to government networks. Known supplier to LockBit and BlackBasta."
    },
    {
      forum: "Exploit",
      govListings: 53,
      avgPrice: 25e4,
      topAccessTypes: ["Zero-day", "VPN", "Supply Chain"],
      riskLevel: "high",
      description: "Premium Russian-language forum. 53 threads in H2 2025. Highest average prices due to zero-day and supply chain access offerings."
    },
    {
      forum: "BreachForums",
      govListings: 30,
      avgPrice: 2500,
      topAccessTypes: ["Credential Dumps", "Email Access", "Database Leaks"],
      riskLevel: "high",
      description: "Data leak marketplace. 30 threads in H2 2025. Lower prices but high volume of .gov credential compilations."
    },
    {
      forum: "XSS",
      govListings: 18,
      avgPrice: 15e3,
      topAccessTypes: ["Webshell", "Database", "CMS"],
      riskLevel: "medium",
      description: "Declining but persistent. 18 threads in H2 2025. Specializes in web application access to state government portals."
    },
    {
      forum: "Telegram/Signal",
      govListings: 50,
      avgPrice: 500,
      topAccessTypes: ["Email Access", "Credentials", "Session Tokens"],
      riskLevel: "high",
      description: "Growing marketplace for low-cost .gov email accounts ($40-$500). Infostealer-harvested credentials sold via encrypted messaging. Used for fake subpoenas."
    }
  ];
}
function getGovBrokerStats() {
  const brokers = GOV_IAB_KNOWLEDGE_BASE;
  const forums = getForumActivityPatterns();
  const accessTypeCounts = /* @__PURE__ */ new Map();
  for (const b of brokers) {
    for (const at of b.accessTypes) {
      accessTypeCounts.set(at, (accessTypeCounts.get(at) || 0) + 1);
    }
  }
  const topAccessTypes = [...accessTypeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([type, count]) => ({ type: type.replace(/_/g, " "), count }));
  const agencyCounts = /* @__PURE__ */ new Map();
  for (const b of brokers) {
    for (const a of b.govTargeting.agencies) {
      agencyCounts.set(a, (agencyCounts.get(a) || 0) + 1);
    }
  }
  const topTargetedAgencies = [...agencyCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([agency, count]) => ({ agency, count }));
  const prices = brokers.flatMap((b) => [b.govTargeting.priceRange.min, b.govTargeting.priceRange.max]);
  const minPrice = Math.min(...prices);
  const maxPrice = Math.max(...prices);
  const avgPrice = Math.round(prices.reduce((s, p) => s + p, 0) / prices.length);
  const riskDist = [
    { level: "Critical (90-100)", count: brokers.filter((b) => b.riskScore >= 90).length },
    { level: "High (75-89)", count: brokers.filter((b) => b.riskScore >= 75 && b.riskScore < 90).length },
    { level: "Medium (50-74)", count: brokers.filter((b) => b.riskScore >= 50 && b.riskScore < 75).length },
    { level: "Low (<50)", count: brokers.filter((b) => b.riskScore < 50).length }
  ];
  return {
    totalKnownBrokers: brokers.length,
    activeBrokers: brokers.filter((b) => {
      const d = new Date(b.lastActive);
      return Date.now() - d.getTime() < 90 * 24 * 60 * 60 * 1e3;
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
      { period: "H2 2024", newListings: 180, priceTrend: "stable" }
    ]
  };
}
function enrichWithGovIntel(listing) {
  const detection = detectGovTargeting(listing);
  if (!detection.isGov) {
    return {
      isGovTarget: false,
      govConfidence: 0,
      riskScore: 0,
      riskFactors: [],
      matchedPatterns: [],
      knownProfile: null
    };
  }
  const risk = calculateGovRiskScore({
    ...listing,
    govConfidence: detection.confidence
  });
  const knownProfile = GOV_IAB_KNOWLEDGE_BASE.find(
    (b) => b.brokerName.toLowerCase() === (listing.brokerName || "").toLowerCase() || b.aliases.some((a) => a.toLowerCase() === (listing.brokerName || "").toLowerCase()) || b.brokerId === listing.brokerId
  ) || null;
  return {
    isGovTarget: true,
    govConfidence: detection.confidence,
    riskScore: risk.score,
    riskFactors: risk.factors,
    matchedPatterns: detection.matchedPatterns,
    knownProfile
  };
}
function getKnownGovBrokers() {
  return [...GOV_IAB_KNOWLEDGE_BASE].sort((a, b) => b.riskScore - a.riskScore);
}
function searchGovBrokers(query) {
  const q = query.toLowerCase();
  return GOV_IAB_KNOWLEDGE_BASE.filter(
    (b) => b.brokerName.toLowerCase().includes(q) || b.aliases.some((a) => a.toLowerCase().includes(q)) || b.notes.toLowerCase().includes(q) || b.govTargeting.agencies.some((a) => a.toLowerCase().includes(q)) || b.linkedGroups.some((g) => g.toLowerCase().includes(q)) || b.attribution.toLowerCase().includes(q)
  );
}
export {
  GOV_IAB_KNOWLEDGE_BASE,
  calculateGovRiskScore,
  detectGovTargeting,
  enrichWithGovIntel,
  getForumActivityPatterns,
  getGovBrokerStats,
  getKnownGovBrokers,
  searchGovBrokers
};
