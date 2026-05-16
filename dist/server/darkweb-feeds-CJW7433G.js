import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import "./chunk-NRYVRXXR.js";
import {
  accessBrokerListings,
  infoOpsCampaigns,
  init_schema,
  threatActors
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/darkweb-feeds.ts
import { eq } from "drizzle-orm";
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function syncAccessBrokers() {
  const db = await requireDb();
  let inserted = 0;
  let updated = 0;
  for (const iab of KNOWN_IABS) {
    const existing = await db.select().from(accessBrokerListings).where(eq(accessBrokerListings.brokerId, iab.brokerId)).limit(1);
    if (existing.length === 0) {
      await db.insert(accessBrokerListings).values({
        brokerId: iab.brokerId,
        brokerName: iab.brokerName,
        aliases: iab.aliases,
        iabDescription: iab.description,
        listingType: iab.listingType,
        accessType: iab.accessType,
        forumSource: iab.forumSource,
        activeForums: iab.activeForums,
        brokerReputation: iab.brokerReputation,
        linkedRansomwareGroups: iab.linkedRansomwareGroups,
        mitreTechniques: iab.mitreTechniques,
        accessLevel: iab.accessLevel,
        iabStatus: iab.status,
        iabFirstSeen: iab.firstSeen,
        iabLastActive: iab.lastActive,
        victimSector: iab.victimSector,
        victimCountry: iab.victimCountry,
        iabConfidence: iab.confidence,
        iabDataSource: "osint_curated"
      });
      inserted++;
    } else {
      await db.update(accessBrokerListings).set({
        brokerName: iab.brokerName,
        aliases: iab.aliases,
        iabDescription: iab.description,
        listingType: iab.listingType,
        accessType: iab.accessType,
        linkedRansomwareGroups: iab.linkedRansomwareGroups,
        mitreTechniques: iab.mitreTechniques,
        iabStatus: iab.status,
        iabLastActive: iab.lastActive,
        iabConfidence: iab.confidence
      }).where(eq(accessBrokerListings.brokerId, iab.brokerId));
      updated++;
    }
  }
  for (const iab of KNOWN_IABS) {
    const actorId = `iab-${iab.brokerId}`;
    const existingActor = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
    if (existingActor.length === 0) {
      await db.insert(threatActors).values({
        actorId,
        name: iab.brokerName,
        aliases: iab.aliases,
        actorType: "access_broker",
        origin: "Multiple",
        description: iab.description,
        motivation: "financial",
        firstSeen: iab.firstSeen,
        lastActive: iab.lastActive,
        threatLevel: iab.confidence >= 90 ? "high" : "medium",
        sophistication: "advanced",
        targetSectors: iab.victimSector ? iab.victimSector.split(", ") : [],
        techniques: iab.mitreTechniques.map((t) => ({ id: t, name: t, tactic: "initial-access" })),
        tools: iab.linkedRansomwareGroups,
        dataSource: "osint_curated",
        confidence: iab.confidence
      });
    }
  }
  const allBrokers = await db.select().from(accessBrokerListings);
  return { inserted, updated, total: allBrokers.length };
}
async function syncInfoOpsCampaigns() {
  const db = await requireDb();
  let inserted = 0;
  let updated = 0;
  for (const io of KNOWN_IO_CAMPAIGNS) {
    const existing = await db.select().from(infoOpsCampaigns).where(eq(infoOpsCampaigns.ioCampaignId, io.campaignId)).limit(1);
    if (existing.length === 0) {
      await db.insert(infoOpsCampaigns).values({
        ioCampaignId: io.campaignId,
        ioCampaignName: io.campaignName,
        ioAliases: io.aliases,
        attributedTo: io.attributedTo,
        sponsorState: io.sponsorState,
        operatorGroup: io.operatorGroup,
        operationType: io.operationType,
        ioStatus: io.status,
        ioTargetCountries: io.targetCountries,
        targetAudiences: io.targetAudiences,
        ioTargetPlatforms: io.targetPlatforms,
        targetNarratives: io.targetNarratives,
        ioTechniques: io.techniques,
        cyberComponent: io.cyberComponent,
        linkedCyberOps: io.linkedCyberOps,
        primarySource: io.primarySource,
        ioStartDate: io.startDate,
        ioEndDate: io.endDate,
        discoveredDate: io.discoveredDate,
        ioThreatLevel: io.threatLevel,
        ioConfidence: io.confidence,
        ioDescription: io.description,
        ioDataSource: "osint_curated"
      });
      inserted++;
    } else {
      await db.update(infoOpsCampaigns).set({
        ioCampaignName: io.campaignName,
        ioAliases: io.aliases,
        ioStatus: io.status,
        targetNarratives: io.targetNarratives,
        ioTechniques: io.techniques,
        ioConfidence: io.confidence,
        ioDescription: io.description
      }).where(eq(infoOpsCampaigns.ioCampaignId, io.campaignId));
      updated++;
    }
  }
  for (const io of KNOWN_IO_CAMPAIGNS) {
    const actorId = `io-${io.campaignId}`;
    const existingActor = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
    if (existingActor.length === 0) {
      await db.insert(threatActors).values({
        actorId,
        name: `${io.operatorGroup} (${io.campaignName})`,
        aliases: io.aliases,
        actorType: "influence_ops",
        origin: io.sponsorState,
        description: io.description,
        motivation: "influence",
        firstSeen: io.startDate,
        lastActive: io.endDate || (/* @__PURE__ */ new Date()).toISOString().slice(0, 7),
        threatLevel: io.threatLevel,
        sophistication: io.confidence >= 90 ? "nation-state" : "advanced",
        targetSectors: io.targetAudiences,
        targetRegions: io.targetCountries,
        techniques: io.linkedCyberOps.length > 0 ? io.linkedCyberOps.map((op) => ({ id: op, name: op, tactic: "influence" })) : [],
        tools: io.techniques,
        dataSource: "osint_curated",
        confidence: io.confidence
      });
    }
  }
  const allCampaigns = await db.select().from(infoOpsCampaigns);
  return { inserted, updated, total: allCampaigns.length };
}
async function syncAllDarkwebFeeds() {
  const accessBrokers = await syncAccessBrokers();
  let infoOps;
  try {
    infoOps = await syncInfoOpsCampaigns();
  } catch (err) {
    console.warn("[FeedSync] Info Ops sync skipped (table may not exist):", err?.message?.slice(0, 120));
    infoOps = { inserted: 0, updated: 0, total: 0 };
  }
  let dailyDarkWeb;
  try {
    const { syncDailyDarkWebFeed } = await import("./dailydarkweb-feed-2FERUYQG.js");
    const result = await syncDailyDarkWebFeed();
    dailyDarkWeb = { fulcrumsec: result.fulcrumsec, actors: result.actors };
  } catch (err) {
    console.error("[DarkwebFeeds] Daily Dark Web sync failed:", err);
  }
  return { accessBrokers, infoOps, dailyDarkWeb };
}
var KNOWN_IABS, KNOWN_IO_CAMPAIGNS;
var init_darkweb_feeds = __esm({
  "server/lib/darkweb-feeds.ts"() {
    init_db();
    init_schema();
    KNOWN_IABS = [
      {
        brokerId: "exotic-lily",
        brokerName: "Exotic Lily",
        aliases: ["EXOTIC LILY", "TA580"],
        description: "Financially motivated initial access broker linked to Conti and Diavol ransomware operations. Uses highly targeted business email compromise (BEC) with spoofed identities and legitimate file-sharing services. Known for impersonating real employees at target organizations using fabricated LinkedIn profiles.",
        listingType: "email_access",
        accessType: "BEC / Phishing",
        forumSource: "direct-partnership",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["conti", "diavol", "bumblebee"],
        mitreTechniques: ["T1566.001", "T1566.002", "T1204.001", "T1204.002", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2021-09",
        lastActive: "2025-12",
        victimSector: "Technology, Healthcare, Finance",
        victimCountry: "US, UK, DE",
        confidence: 90
      },
      {
        brokerId: "zebra2104",
        brokerName: "Zebra2104",
        aliases: ["Zebra2104"],
        description: "Infrastructure-as-a-service broker providing hosting and domain infrastructure to multiple ransomware and APT groups including MountLocker, Phobos, StrongPity, and APT29. Operates shared infrastructure that connects seemingly unrelated threat actors.",
        listingType: "other",
        accessType: "Infrastructure-as-a-Service",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["mountlocker", "phobos", "strongpity"],
        mitreTechniques: ["T1583.001", "T1583.003", "T1584.001", "T1584.004"],
        accessLevel: "unknown",
        status: "active",
        firstSeen: "2020-01",
        lastActive: "2025-06",
        confidence: 80
      },
      {
        brokerId: "prophet-spider",
        brokerName: "Prophet Spider",
        aliases: ["Prophet Spider", "UNC961"],
        description: "Opportunistic initial access broker that exploits public-facing web applications (Log4Shell, Citrix vulnerabilities) to gain access, then sells it to ransomware operators. Known for exploiting CVE-2021-44228 (Log4j) and CVE-2019-19781 (Citrix ADC) at scale.",
        listingType: "webshell",
        accessType: "Web Application Exploitation",
        forumSource: "exploit.in",
        activeForums: ["exploit.in", "xss.is"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["blackcat", "hive", "grief"],
        mitreTechniques: ["T1190", "T1505.003", "T1059.001", "T1021.002"],
        accessLevel: "local_admin",
        status: "active",
        firstSeen: "2020-05",
        lastActive: "2025-11",
        victimSector: "Healthcare, Education, Government",
        victimCountry: "US, CA, AU",
        confidence: 85
      },
      {
        brokerId: "dev-0569",
        brokerName: "DEV-0569",
        aliases: ["DEV-0569", "Storm-0569"],
        description: "Access broker distributing malware through Google Ads and SEO poisoning (malvertising). Delivers BATLOADER and Royal ransomware payloads via trojanized software installers. Pioneered abuse of legitimate ad platforms for initial access delivery.",
        listingType: "other",
        accessType: "Malvertising / SEO Poisoning",
        forumSource: "direct-partnership",
        activeForums: ["private"],
        brokerReputation: "rising",
        linkedRansomwareGroups: ["royal", "blackbasta"],
        mitreTechniques: ["T1189", "T1204.002", "T1036.005", "T1059.001", "T1547.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2022-08",
        lastActive: "2025-10",
        victimSector: "Multiple",
        victimCountry: "US, UK, DE, FR",
        confidence: 80
      },
      {
        brokerId: "raspberry-robin",
        brokerName: "Raspberry Robin",
        aliases: ["Raspberry Robin", "QNAP Worm", "DEV-0856"],
        description: "Worm-based access broker spreading via infected USB drives and compromised QNAP NAS devices. Provides initial access to multiple ransomware affiliates including Clop, LockBit, and TrueBot. One of the most widely distributed malware loaders in enterprise environments.",
        listingType: "other",
        accessType: "USB Worm / Loader",
        forumSource: "direct-partnership",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["clop", "lockbit", "truebot", "flawed-ammyy"],
        mitreTechniques: ["T1091", "T1059.001", "T1218.011", "T1055", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2021-09",
        lastActive: "2026-01",
        victimSector: "Manufacturing, Finance, Government",
        victimCountry: "US, DE, JP, UK",
        confidence: 90
      },
      {
        brokerId: "qakbot-operators",
        brokerName: "QakBot Operators",
        aliases: ["QBot", "Qakbot", "Pinkslipbot", "TA570"],
        description: "Long-running banking trojan turned access broker. QakBot operators sell network access to ransomware groups including BlackBasta, Royal, and Egregor. Despite FBI takedown in Aug 2023, the botnet has shown signs of resurgence. Distributed primarily via phishing with OneNote and PDF lures.",
        listingType: "other",
        accessType: "Botnet / Loader",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["blackbasta", "royal", "egregor", "prolock", "revil"],
        mitreTechniques: ["T1566.001", "T1204.002", "T1059.001", "T1055", "T1021.002", "T1003.001"],
        accessLevel: "domain_admin",
        status: "active",
        firstSeen: "2008-01",
        lastActive: "2025-12",
        victimSector: "Finance, Healthcare, Manufacturing",
        victimCountry: "US, UK, DE, IT, FR",
        confidence: 95
      },
      {
        brokerId: "trickbot-operators",
        brokerName: "TrickBot / BazarLoader Operators",
        aliases: ["TrickBot", "BazarLoader", "BazarBackdoor", "ITG23", "Wizard Spider Affiliates"],
        description: "Operators of the TrickBot/BazarLoader malware ecosystem, historically the primary access provider for Conti ransomware. After Conti's dissolution, continued providing access to successor groups including Royal, BlackBasta, and Diavol. Key members sanctioned by US/UK in 2023.",
        listingType: "other",
        accessType: "Botnet / Loader",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["conti", "ryuk", "royal", "blackbasta", "diavol"],
        mitreTechniques: ["T1566.001", "T1059.001", "T1055", "T1003.001", "T1021.002", "T1486"],
        accessLevel: "domain_admin",
        status: "active",
        firstSeen: "2016-10",
        lastActive: "2025-08",
        victimSector: "Healthcare, Finance, Government, Education",
        victimCountry: "US, UK, CA, AU, DE",
        confidence: 95
      },
      {
        brokerId: "emotet-operators",
        brokerName: "Emotet Operators",
        aliases: ["Emotet", "Heodo", "TA542", "Mealybug"],
        description: "Operators of the Emotet botnet, one of the most prolific malware distribution networks. Originally a banking trojan, evolved into a loader-for-hire providing initial access to ransomware groups. Taken down by Europol in Jan 2021 but resurfaced in Nov 2021. Continues to deliver payloads for multiple ransomware affiliates.",
        listingType: "email_access",
        accessType: "Botnet / Spam Loader",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["ryuk", "conti", "quantum", "blackcat"],
        mitreTechniques: ["T1566.001", "T1204.002", "T1059.005", "T1055", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2014-06",
        lastActive: "2025-09",
        victimSector: "Multiple",
        victimCountry: "US, JP, DE, UK, IT, FR",
        confidence: 95
      },
      {
        brokerId: "scattered-spider-iab",
        brokerName: "Scattered Spider (IAB Operations)",
        aliases: ["Scattered Spider", "UNC3944", "0ktapus", "Starfraud", "Muddled Libra"],
        description: "Young English-speaking threat group operating as both direct attackers and access brokers. Specialize in social engineering help desks, SIM swapping, and MFA fatigue attacks to gain access to enterprise environments. Known for targeting Okta, Microsoft 365, and cloud infrastructure. Sold access to ALPHV/BlackCat ransomware operators.",
        listingType: "cloud_access",
        accessType: "Social Engineering / SIM Swap",
        forumSource: "telegram",
        activeForums: ["telegram", "discord", "private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["alphv", "blackcat", "qilin"],
        mitreTechniques: ["T1566.004", "T1621", "T1078.004", "T1199", "T1556.006"],
        accessLevel: "domain_admin",
        status: "active",
        firstSeen: "2022-03",
        lastActive: "2026-01",
        victimSector: "Technology, Telecom, Finance, Entertainment",
        victimCountry: "US, UK",
        confidence: 90
      },
      {
        brokerId: "ftp-iab",
        brokerName: "FTP (Forum IAB Operator)",
        aliases: ["ftp", "ftpbrute"],
        description: "Prolific forum-based initial access broker operating on Exploit.in and XSS.is. Specializes in selling RDP and VPN access to corporate networks, typically obtained through credential brute-forcing and purchasing stolen credentials from infostealer logs. One of the most active sellers on Russian-language cybercrime forums.",
        listingType: "rdp_access",
        accessType: "RDP / VPN Credential Access",
        forumSource: "exploit.in",
        activeForums: ["exploit.in", "xss.is"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["lockbit", "alphv", "play"],
        mitreTechniques: ["T1110.001", "T1078.001", "T1133", "T1021.001"],
        accessLevel: "local_admin",
        status: "active",
        firstSeen: "2019-03",
        lastActive: "2026-01",
        victimSector: "Multiple",
        victimCountry: "US, UK, CA, AU, DE, FR",
        confidence: 85
      },
      {
        brokerId: "kelvin-security",
        brokerName: "Kelvin Security",
        aliases: ["KelvinSecurity", "KelvinSecTeam"],
        description: "Hacktivist-turned-access-broker group selling compromised databases, network access, and stolen data on darkweb forums and Telegram. Known for targeting government institutions, military, and critical infrastructure across Latin America, Europe, and Asia. Operates both as data brokers and access sellers.",
        listingType: "database_access",
        accessType: "Database / Network Access",
        forumSource: "breachforums",
        activeForums: ["breachforums", "telegram", "raidforums-successor"],
        brokerReputation: "established",
        linkedRansomwareGroups: [],
        mitreTechniques: ["T1190", "T1078", "T1530", "T1213"],
        accessLevel: "unknown",
        status: "active",
        firstSeen: "2020-01",
        lastActive: "2025-12",
        victimSector: "Government, Military, Telecom",
        victimCountry: "CO, MX, BR, IT, IN",
        confidence: 80
      },
      {
        brokerId: "baphomet-iab",
        brokerName: "Baphomet (BreachForums Admin)",
        aliases: ["Baphomet"],
        description: "Administrator of BreachForums who also operates as an access broker. Facilitates the sale of compromised network access and stolen databases through the forum. Took over BreachForums after the arrest of Pompompurin. The forum serves as a major marketplace for IAB listings.",
        listingType: "other",
        accessType: "Forum Marketplace Operator",
        forumSource: "breachforums",
        activeForums: ["breachforums"],
        brokerReputation: "established",
        linkedRansomwareGroups: [],
        mitreTechniques: [],
        accessLevel: "unknown",
        status: "law_enforcement",
        firstSeen: "2022-06",
        lastActive: "2024-05",
        confidence: 75
      },
      {
        brokerId: "icedid-operators",
        brokerName: "IcedID / BokBot Operators",
        aliases: ["IcedID", "BokBot", "TA551"],
        description: "Operators of the IcedID banking trojan turned initial access loader. Provides access to enterprise networks for ransomware deployment. Known for thread-hijacking email campaigns and delivering payloads for Conti, Quantum, and XingLocker ransomware groups.",
        listingType: "email_access",
        accessType: "Botnet / Loader",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["conti", "quantum", "xinglocker", "nokoyawa"],
        mitreTechniques: ["T1566.001", "T1204.002", "T1059.001", "T1055", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2017-04",
        lastActive: "2025-06",
        victimSector: "Finance, Healthcare, Legal",
        victimCountry: "US, UK, CA",
        confidence: 90
      },
      {
        brokerId: "gootloader-operators",
        brokerName: "GootLoader Operators",
        aliases: ["GootLoader", "DEV-0243", "TA505-affiliate"],
        description: "Operators of the GootLoader malware delivery framework that uses SEO poisoning to lure victims to compromised WordPress sites hosting fake legal document downloads. Provides initial access for REvil, Cobalt Strike, and other post-exploitation frameworks.",
        listingType: "other",
        accessType: "SEO Poisoning / Watering Hole",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["revil", "blacksuit"],
        mitreTechniques: ["T1189", "T1059.007", "T1059.001", "T1027", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2020-12",
        lastActive: "2025-11",
        victimSector: "Legal, Finance, Healthcare",
        victimCountry: "US, UK, AU, CA",
        confidence: 85
      },
      {
        brokerId: "socgholish-operators",
        brokerName: "SocGholish / FakeUpdates Operators",
        aliases: ["SocGholish", "FakeUpdates", "TA569", "UNC1543"],
        description: "Operators of the SocGholish (FakeUpdates) malware framework that injects fake browser update prompts into compromised legitimate websites. Serves as an initial access vector for Evil Corp (DEV-0243) and other ransomware affiliates. Compromises thousands of websites simultaneously.",
        listingType: "webshell",
        accessType: "Drive-by Download / Fake Updates",
        forumSource: "private-network",
        activeForums: ["private"],
        brokerReputation: "established",
        linkedRansomwareGroups: ["wasted-locker", "lockbit", "blackbasta"],
        mitreTechniques: ["T1189", "T1204.001", "T1059.007", "T1059.001", "T1071.001"],
        accessLevel: "user",
        status: "active",
        firstSeen: "2018-01",
        lastActive: "2026-01",
        victimSector: "Multiple",
        victimCountry: "US, UK, CA, AU",
        confidence: 90
      }
    ];
    KNOWN_IO_CAMPAIGNS = [
      {
        campaignId: "ira-2016-election",
        campaignName: "Internet Research Agency \u2014 2016 US Election Interference",
        aliases: ["IRA", "Project Lakhta", "Troll Factory"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "Internet Research Agency (IRA)",
        operationType: "election_interference",
        status: "attributed",
        targetCountries: ["US"],
        targetAudiences: ["voters", "African-American communities", "conservative voters", "progressive voters"],
        targetPlatforms: ["Facebook", "Twitter", "Instagram", "YouTube", "Reddit", "Tumblr"],
        targetNarratives: ["racial division", "political polarization", "election delegitimization", "anti-Clinton", "pro-Trump", "anti-immigration"],
        techniques: ["fake accounts", "bot networks", "paid advertising", "community infiltration", "event organization"],
        cyberComponent: true,
        linkedCyberOps: ["apt28", "apt29"],
        primarySource: "Mueller Report / US DOJ Indictment",
        startDate: "2014-01",
        endDate: "2018-12",
        discoveredDate: "2017-09",
        threatLevel: "critical",
        confidence: 99,
        description: "The Internet Research Agency (IRA), funded by Yevgeny Prigozhin, conducted a massive influence operation targeting the 2016 US presidential election. The operation involved hundreds of employees creating fake American personas on social media, organizing real-world rallies, and purchasing political advertisements. The campaign reached tens of millions of Americans and was designed to sow discord and influence voter behavior."
      },
      {
        campaignId: "ghostwriter",
        campaignName: "Ghostwriter",
        aliases: ["UNC1151", "Ghostwriter"],
        attributedTo: "Belarus / Russia",
        sponsorState: "Belarus",
        operatorGroup: "UNC1151 (GRU-linked)",
        operationType: "hack_and_leak",
        status: "active",
        targetCountries: ["PL", "LT", "LV", "DE", "UA"],
        targetAudiences: ["NATO member state citizens", "military personnel", "government officials"],
        targetPlatforms: ["compromised news sites", "social media", "email"],
        targetNarratives: ["anti-NATO", "anti-US military presence", "anti-EU", "pro-Russia"],
        techniques: ["website compromise", "credential phishing", "fake news articles", "social media manipulation", "email spoofing"],
        cyberComponent: true,
        linkedCyberOps: ["unc1151", "apt28"],
        primarySource: "Mandiant / FireEye",
        startDate: "2017-03",
        discoveredDate: "2020-07",
        threatLevel: "high",
        confidence: 90,
        description: "Ghostwriter is a long-running influence operation attributed to Belarus (with suspected Russian GRU support) that targets NATO member states, particularly Poland, Lithuania, and Latvia. The operation compromises legitimate news websites and social media accounts to publish fabricated articles and leaked documents designed to undermine NATO solidarity and US military presence in Europe."
      },
      {
        campaignId: "secondary-infektion",
        campaignName: "Secondary Infektion",
        aliases: ["Secondary Infektion"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "GRU / SVR (suspected)",
        operationType: "disinformation",
        status: "attributed",
        targetCountries: ["US", "UK", "DE", "FR", "UA", "EU"],
        targetAudiences: ["general public", "journalists", "policy makers"],
        targetPlatforms: ["Reddit", "Medium", "Quora", "various forums", "fake blogs"],
        targetNarratives: ["anti-Ukraine", "anti-NATO", "EU division", "US political scandals"],
        techniques: ["forged documents", "fake blog posts", "forum manipulation", "one-shot accounts"],
        cyberComponent: false,
        linkedCyberOps: [],
        primarySource: "Graphika / Atlantic Council DFRLab",
        startDate: "2014-01",
        endDate: "2020-06",
        discoveredDate: "2019-06",
        threatLevel: "high",
        confidence: 85,
        description: "Secondary Infektion was a Russian influence operation that used forged documents and fabricated stories planted across dozens of platforms including Reddit, Medium, and Quora. Unlike the IRA, this operation used 'one-shot' disposable accounts rather than building persistent personas. The campaign spread anti-Ukraine, anti-NATO, and divisive narratives across Western countries."
      },
      {
        campaignId: "doppelganger",
        campaignName: "Doppelganger",
        aliases: ["Doppelganger", "Recent Reliable News"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "Social Design Agency / Structura",
        operationType: "disinformation",
        status: "active",
        targetCountries: ["DE", "FR", "US", "UK", "IL", "UA"],
        targetAudiences: ["European citizens", "news consumers"],
        targetPlatforms: ["Facebook", "Twitter/X", "cloned news websites", "Telegram"],
        targetNarratives: ["anti-Ukraine aid", "energy crisis blame", "anti-immigration", "EU instability"],
        techniques: ["website cloning", "typosquatting news domains", "paid social media ads", "AI-generated content"],
        cyberComponent: false,
        linkedCyberOps: [],
        primarySource: "EU DisinfoLab / Meta Threat Report",
        startDate: "2022-05",
        discoveredDate: "2022-09",
        threatLevel: "critical",
        confidence: 95,
        description: "Doppelganger is an ongoing Russian influence operation that creates convincing clones of legitimate European news websites (Der Spiegel, Bild, Le Monde, etc.) to publish pro-Russian disinformation. The operation uses typosquatted domains and paid social media advertising to drive traffic to fake articles designed to undermine European support for Ukraine."
      },
      {
        campaignId: "spamouflage-dragon",
        campaignName: "Spamouflage Dragon",
        aliases: ["Spamouflage", "DRAGONBRIDGE", "Storm-1376"],
        attributedTo: "China",
        sponsorState: "China",
        operatorGroup: "PRC-linked (MPS/MSS suspected)",
        operationType: "influence",
        status: "active",
        targetCountries: ["US", "TW", "HK", "AU", "CA", "JP"],
        targetAudiences: ["Chinese diaspora", "Western public", "Taiwanese citizens"],
        targetPlatforms: ["YouTube", "Facebook", "Twitter/X", "TikTok", "Reddit", "Medium"],
        targetNarratives: ["pro-CCP", "anti-US", "Taiwan reunification", "COVID-19 origin deflection", "anti-democracy protests"],
        techniques: ["mass bot networks", "AI-generated content", "deepfake videos", "coordinated inauthentic behavior", "platform manipulation"],
        cyberComponent: false,
        linkedCyberOps: ["apt41", "apt31"],
        primarySource: "Mandiant / Graphika / Meta",
        startDate: "2019-06",
        discoveredDate: "2019-08",
        threatLevel: "high",
        confidence: 90,
        description: "Spamouflage Dragon (also tracked as DRAGONBRIDGE by Mandiant) is the largest known Chinese influence operation, using thousands of accounts across multiple platforms to promote pro-CCP narratives and attack critics of the Chinese government. The operation has evolved to use AI-generated content and deepfake news anchors."
      },
      {
        campaignId: "iuvm-iran",
        campaignName: "IUVM / Endless Mayfly",
        aliases: ["IUVM", "International Union of Virtual Media", "Endless Mayfly", "Liberty Front Press"],
        attributedTo: "Iran",
        sponsorState: "Iran",
        operatorGroup: "IRGC-linked media operations",
        operationType: "influence",
        status: "active",
        targetCountries: ["US", "IL", "SA", "UK", "IQ"],
        targetAudiences: ["Middle Eastern diaspora", "Western public", "anti-Israel activists"],
        targetPlatforms: ["Facebook", "Twitter/X", "Instagram", "fake news websites", "Telegram"],
        targetNarratives: ["anti-Israel", "anti-Saudi", "anti-US foreign policy", "pro-Palestinian", "pro-IRGC"],
        techniques: ["fake news websites", "social media personas", "impersonation of journalists", "hashtag hijacking"],
        cyberComponent: true,
        linkedCyberOps: ["apt33", "apt34", "apt35"],
        primarySource: "Citizen Lab / FireEye / Meta",
        startDate: "2016-01",
        discoveredDate: "2018-08",
        threatLevel: "high",
        confidence: 85,
        description: "IUVM (International Union of Virtual Media) is an Iranian influence operation network linked to the IRGC that operates fake news websites and social media accounts to promote pro-Iran narratives and undermine US, Israeli, and Saudi Arabian interests. The operation impersonates legitimate journalists and news outlets."
      },
      {
        campaignId: "storm-1679",
        campaignName: "Storm-1679 (Olympics Disinformation)",
        aliases: ["Storm-1679"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "Storm-1679",
        operationType: "disinformation",
        status: "active",
        targetCountries: ["FR", "US", "Global"],
        targetAudiences: ["sports fans", "general public", "IOC stakeholders"],
        targetPlatforms: ["Telegram", "Twitter/X", "YouTube", "fake news sites"],
        targetNarratives: ["anti-Olympics", "anti-France", "terrorism fears", "IOC corruption"],
        techniques: ["deepfake videos", "fake documentaries", "AI-generated content", "impersonation of news outlets"],
        cyberComponent: false,
        linkedCyberOps: [],
        primarySource: "Microsoft Threat Intelligence",
        startDate: "2023-06",
        discoveredDate: "2024-06",
        threatLevel: "medium",
        confidence: 85,
        description: "Storm-1679 is a Russian influence operation that targeted the 2024 Paris Olympics with disinformation campaigns including deepfake videos impersonating Tom Cruise, fake Netflix documentaries about IOC corruption, and fabricated terrorism threats. The operation aimed to discourage attendance and undermine France's international reputation."
      },
      {
        campaignId: "apt28-hack-leak",
        campaignName: "APT28 Hack-and-Leak Operations",
        aliases: ["Fancy Bear Leaks", "CyberCaliphate", "DCLeaks", "Guccifer 2.0"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "GRU Unit 26165 (APT28)",
        operationType: "hack_and_leak",
        status: "active",
        targetCountries: ["US", "FR", "DE", "UA", "GE"],
        targetAudiences: ["voters", "journalists", "political parties"],
        targetPlatforms: ["WikiLeaks", "DCLeaks", "Guccifer 2.0 blog", "social media"],
        targetNarratives: ["political corruption", "election manipulation", "anti-NATO"],
        techniques: ["spear-phishing", "credential harvesting", "strategic leaking", "false flag personas", "timing manipulation"],
        cyberComponent: true,
        linkedCyberOps: ["apt28"],
        primarySource: "CrowdStrike / US Intelligence Community",
        startDate: "2015-03",
        discoveredDate: "2016-06",
        threatLevel: "critical",
        confidence: 95,
        description: "APT28 (GRU Unit 26165) conducts hybrid cyber-influence operations combining network intrusions with strategic leaking of stolen documents. Most notably, the 2016 DNC hack and subsequent leaks via DCLeaks and Guccifer 2.0 personas. The group continues to target political organizations, think tanks, and government entities worldwide."
      },
      {
        campaignId: "fox-kitten-io",
        campaignName: "Fox Kitten IO / IRGC Election Interference",
        aliases: ["Fox Kitten", "Pioneer Kitten", "IRGC Cyber-IO"],
        attributedTo: "Iran",
        sponsorState: "Iran",
        operatorGroup: "IRGC-CEC",
        operationType: "election_interference",
        status: "active",
        targetCountries: ["US", "IL"],
        targetAudiences: ["US voters", "Israeli citizens"],
        targetPlatforms: ["email", "social media", "fake websites"],
        targetNarratives: ["anti-Israel", "US election chaos", "voter intimidation"],
        techniques: ["voter intimidation emails", "fake Proud Boys personas", "hack-and-leak", "website defacement"],
        cyberComponent: true,
        linkedCyberOps: ["apt33", "apt35"],
        primarySource: "FBI / CISA / ODNI Joint Advisory",
        startDate: "2020-09",
        discoveredDate: "2020-10",
        threatLevel: "high",
        confidence: 90,
        description: "Iranian IRGC-linked cyber actors conducted election interference operations targeting the 2020 and 2024 US elections. Operations included sending threatening voter intimidation emails impersonating the Proud Boys, compromising state election websites, and conducting hack-and-leak operations against political campaigns."
      },
      {
        campaignId: "chinese-police-stations",
        campaignName: "Chinese Overseas Police Service Stations",
        aliases: ["Operation Fox Hunt", "Operation Sky Net", "Overseas Chinese Service Centers"],
        attributedTo: "China",
        sponsorState: "China",
        operatorGroup: "MPS / United Front Work Department",
        operationType: "influence",
        status: "ongoing",
        targetCountries: ["US", "CA", "UK", "NL", "IE", "JP", "AU"],
        targetAudiences: ["Chinese diaspora", "dissidents", "Uyghur community", "Tibetan community"],
        targetPlatforms: ["WeChat", "physical locations", "phone calls", "in-person visits"],
        targetNarratives: ["repatriation pressure", "surveillance", "transnational repression"],
        techniques: ["physical intimidation", "family coercion", "surveillance", "community infiltration", "WeChat monitoring"],
        cyberComponent: true,
        linkedCyberOps: ["apt10", "apt31"],
        primarySource: "Safeguard Defenders / FBI",
        startDate: "2018-01",
        discoveredDate: "2022-09",
        threatLevel: "high",
        confidence: 85,
        description: "China operates undeclared 'overseas police service stations' in dozens of countries, used to monitor, harass, and coerce Chinese nationals abroad into returning to China. These stations, linked to the Ministry of Public Security, conduct transnational repression operations targeting dissidents, Uyghurs, and other communities critical of the CCP."
      },
      {
        campaignId: "sandworm-prestige",
        campaignName: "Sandworm Psychological Operations (Ukraine)",
        aliases: ["CyberArmyofRussia_Reborn", "Solntsepek"],
        attributedTo: "Russia",
        sponsorState: "Russia",
        operatorGroup: "GRU Unit 74455 (Sandworm)",
        operationType: "cyber_espionage_io",
        status: "active",
        targetCountries: ["UA", "PL", "EU"],
        targetAudiences: ["Ukrainian citizens", "European public", "military personnel"],
        targetPlatforms: ["Telegram", "social media", "compromised infrastructure"],
        targetNarratives: ["Ukrainian government incompetence", "futility of resistance", "Western abandonment"],
        techniques: ["destructive cyberattacks with IO amplification", "hacktivist front groups", "infrastructure disruption messaging"],
        cyberComponent: true,
        linkedCyberOps: ["sandworm"],
        primarySource: "Mandiant / CERT-UA / Microsoft",
        startDate: "2022-02",
        discoveredDate: "2022-02",
        threatLevel: "critical",
        confidence: 95,
        description: "Sandworm (GRU Unit 74455) conducts hybrid cyber-IO operations against Ukraine, combining destructive cyberattacks on critical infrastructure with psychological operations through hacktivist front groups like CyberArmyofRussia_Reborn and Solntsepek. These operations aim to demoralize the Ukrainian population and demonstrate Russian cyber capabilities."
      },
      {
        campaignId: "north-korea-crypto-io",
        campaignName: "DPRK Cryptocurrency & Tech Worker Infiltration",
        aliases: ["Famous Chollima", "Wagemole", "Nickel Academy"],
        attributedTo: "North Korea",
        sponsorState: "North Korea",
        operatorGroup: "RGB / Lazarus Group affiliates",
        operationType: "other",
        status: "active",
        targetCountries: ["US", "UK", "AU", "CA", "DE", "JP"],
        targetAudiences: ["tech companies", "crypto firms", "remote hiring managers"],
        targetPlatforms: ["LinkedIn", "GitHub", "freelance platforms", "job boards"],
        targetNarratives: ["legitimate employment", "technical competence"],
        techniques: ["fake identities", "AI-enhanced interviews", "stolen credentials", "insider access"],
        cyberComponent: true,
        linkedCyberOps: ["lazarus-group", "apt38"],
        primarySource: "FBI / CrowdStrike / Mandiant",
        startDate: "2020-01",
        discoveredDate: "2023-07",
        threatLevel: "high",
        confidence: 90,
        description: "North Korean operatives pose as legitimate IT workers to infiltrate Western companies, generating revenue for the DPRK regime and gaining insider access for espionage and theft. Thousands of DPRK IT workers use stolen identities and AI tools to secure remote employment at tech and crypto companies, funneling millions in wages to Pyongyang while potentially exfiltrating sensitive data."
      }
    ];
  }
});
init_darkweb_feeds();
export {
  syncAccessBrokers,
  syncAllDarkwebFeeds,
  syncInfoOpsCampaigns
};
