import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  ransomwareEvents,
  ransomwareGroups,
  threatActorIocs,
  threatActors,
  threatGroupEvents
} from "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/dailydarkweb-feed.ts
import { eq, sql } from "drizzle-orm";
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function syncFulcrumsec() {
  const db = await requireDb();
  let iocsInserted = 0;
  let eventsInserted = 0;
  let breachEventsInserted = 0;
  const [existing] = await db.select().from(threatActors).where(eq(threatActors.actorId, FULCRUMSEC_ACTOR.actorId)).limit(1);
  if (!existing) {
    await db.insert(threatActors).values({
      actorId: FULCRUMSEC_ACTOR.actorId,
      name: FULCRUMSEC_ACTOR.name,
      aliases: FULCRUMSEC_ACTOR.aliases,
      actorType: FULCRUMSEC_ACTOR.actorType,
      origin: FULCRUMSEC_ACTOR.origin,
      description: FULCRUMSEC_ACTOR.description,
      motivation: FULCRUMSEC_ACTOR.motivation,
      firstSeen: FULCRUMSEC_ACTOR.firstSeen,
      lastActive: FULCRUMSEC_ACTOR.lastActive,
      threatLevel: FULCRUMSEC_ACTOR.threatLevel,
      sophistication: FULCRUMSEC_ACTOR.sophistication,
      targetSectors: FULCRUMSEC_ACTOR.targetSectors,
      targetRegions: FULCRUMSEC_ACTOR.targetRegions,
      techniques: FULCRUMSEC_ACTOR.techniques,
      tools: FULCRUMSEC_ACTOR.tools,
      malware: FULCRUMSEC_ACTOR.malware,
      activityTimeline: FULCRUMSEC_ACTOR.activityTimeline,
      dataSource: "dailydarkweb_osint",
      confidence: FULCRUMSEC_ACTOR.confidence
    });
  } else {
    await db.update(threatActors).set({
      aliases: FULCRUMSEC_ACTOR.aliases,
      description: FULCRUMSEC_ACTOR.description,
      targetSectors: FULCRUMSEC_ACTOR.targetSectors,
      targetRegions: FULCRUMSEC_ACTOR.targetRegions,
      techniques: FULCRUMSEC_ACTOR.techniques,
      tools: FULCRUMSEC_ACTOR.tools,
      activityTimeline: FULCRUMSEC_ACTOR.activityTimeline,
      confidence: FULCRUMSEC_ACTOR.confidence
    }).where(eq(threatActors.actorId, FULCRUMSEC_ACTOR.actorId));
  }
  for (const ioc of FULCRUMSEC_IOCS) {
    const [existingIoc] = await db.select().from(threatActorIocs).where(sql`${threatActorIocs.actorId} = ${ioc.actorId} AND ${threatActorIocs.value} = ${ioc.value}`).limit(1);
    if (!existingIoc) {
      await db.insert(threatActorIocs).values({
        actorId: ioc.actorId,
        iocType: ioc.type,
        value: ioc.value,
        description: ioc.description,
        iocFirstSeen: ioc.firstSeen,
        iocConfidence: ioc.confidence,
        source: ioc.source
      });
      iocsInserted++;
    }
  }
  for (const evt of FULCRUMSEC_EVENTS) {
    const [existingEvt] = await db.select().from(threatGroupEvents).where(sql`${threatGroupEvents.tgeActorId} = ${evt.actorId} AND ${threatGroupEvents.tgeTitle} = ${evt.title}`).limit(1);
    if (!existingEvt) {
      await db.insert(threatGroupEvents).values({
        tgeActorId: evt.actorId,
        eventType: evt.eventType,
        tgeTitle: evt.title,
        tgeDescription: evt.description,
        tgeSeverity: evt.severity,
        tgeVictimName: evt.victimName,
        tgeVictimSector: evt.victimSector,
        tgeVictimCountry: evt.victimCountry,
        tgeMitreTechniques: evt.mitreTechniques,
        tgeIocs: evt.iocs,
        tgeSource: evt.source,
        tgeSourceUrl: evt.sourceUrl,
        tgeConfidence: evt.confidence,
        eventDate: new Date(evt.eventDate).toISOString()
      });
      eventsInserted++;
    }
  }
  const [existingRw] = await db.select().from(ransomwareGroups).where(eq(ransomwareGroups.groupName, "FULCRUMSEC")).limit(1);
  if (!existingRw) {
    await db.insert(ransomwareGroups).values({
      groupName: "FULCRUMSEC",
      aliases: ["The Threat Thespians", "FulcrumSec"],
      ransomwareFamily: "Data Extortion",
      extortionModel: "double",
      totalVictims: 4,
      victims7D: 1,
      victims30D: 1,
      activityScore: 72,
      trend: "active",
      rwThreatLevel: "high",
      topSectors: ["Legal", "Technology", "Electronics", "FinTech", "Military/Industrial"],
      topCountries: ["US", "AU", "UK"],
      associatedMalware: ["React2Shell exploit"],
      knownInfrastructure: ["fulcrumsec.net (clearnet)", "gsgot6tua7ffammwdv6vpxkog32b4z7qivtqkxz55afq2hkt2o24w5yd.onion (TOR DLS)", "t.me/fulcrumsec (Telegram)"],
      calderaActorId: "fulcrumsec",
      rwDataSource: "dailydarkweb_osint",
      rwConfidence: 85,
      rwFirstSeen: "2025-09",
      rwLastActive: "2026-03"
    });
  }
  for (const evt of FULCRUMSEC_EVENTS) {
    if (evt.eventType === "attack" && evt.victimName) {
      const [existingRe] = await db.select().from(ransomwareEvents).where(sql`${ransomwareEvents.reGroupName} = 'FULCRUMSEC' AND ${ransomwareEvents.victimName} = ${evt.victimName}`).limit(1);
      if (!existingRe) {
        await db.insert(ransomwareEvents).values({
          reGroupName: "FULCRUMSEC",
          victimName: evt.victimName,
          reCountry: evt.victimCountry,
          reSector: evt.victimSector,
          reDescription: evt.description,
          publishedAt: new Date(evt.eventDate).toISOString(),
          reSource: "dailydarkweb_osint",
          verified: 1
        });
        breachEventsInserted++;
      }
    }
  }
  console.log(`[DailyDarkWeb] FULCRUMSEC sync: actor=${!existing ? "new" : "updated"}, iocs=${iocsInserted}, events=${eventsInserted}, breachEvents=${breachEventsInserted}`);
  return { actor: true, iocs: iocsInserted, events: eventsInserted, breachEvents: breachEventsInserted };
}
async function syncDailyDarkWebActors() {
  const db = await requireDb();
  let actorsInserted = 0;
  let eventsInserted = 0;
  let breachEventsInserted = 0;
  for (const actor of DAILYDARKWEB_ACTORS) {
    const [existing] = await db.select().from(threatActors).where(eq(threatActors.actorId, actor.actorId)).limit(1);
    if (!existing) {
      await db.insert(threatActors).values({
        actorId: actor.actorId,
        name: actor.name,
        aliases: actor.aliases,
        actorType: actor.actorType,
        origin: actor.origin,
        description: actor.description,
        motivation: actor.motivation,
        firstSeen: actor.firstSeen,
        lastActive: actor.lastActive,
        threatLevel: actor.threatLevel,
        sophistication: actor.sophistication,
        targetSectors: actor.targetSectors,
        targetRegions: actor.targetRegions,
        techniques: actor.techniques,
        tools: actor.tools,
        malware: actor.malware,
        activityTimeline: actor.activityTimeline,
        dataSource: "dailydarkweb_osint",
        confidence: actor.confidence
      });
      actorsInserted++;
    } else {
      await db.update(threatActors).set({
        activityTimeline: actor.activityTimeline,
        description: actor.description
      }).where(eq(threatActors.actorId, actor.actorId));
    }
  }
  for (const evt of DAILYDARKWEB_EVENTS) {
    const [existingEvt] = await db.select().from(threatGroupEvents).where(sql`${threatGroupEvents.tgeActorId} = ${evt.actorId} AND ${threatGroupEvents.tgeTitle} = ${evt.title}`).limit(1);
    if (!existingEvt) {
      await db.insert(threatGroupEvents).values({
        tgeActorId: evt.actorId,
        eventType: evt.eventType,
        tgeTitle: evt.title,
        tgeDescription: evt.description,
        tgeSeverity: evt.severity,
        tgeVictimName: evt.victimName,
        tgeVictimSector: evt.victimSector,
        tgeVictimCountry: evt.victimCountry,
        tgeMitreTechniques: evt.mitreTechniques,
        tgeIocs: evt.iocs,
        tgeSource: evt.source,
        tgeSourceUrl: evt.sourceUrl,
        tgeConfidence: evt.confidence,
        eventDate: new Date(evt.eventDate).toISOString()
      });
      eventsInserted++;
    }
  }
  for (const evt of DAILYDARKWEB_EVENTS) {
    if (evt.eventType === "attack" && evt.victimName) {
      const actorName = DAILYDARKWEB_ACTORS.find((a) => a.actorId === evt.actorId)?.name || evt.actorId;
      const [existingRe] = await db.select().from(ransomwareEvents).where(sql`${ransomwareEvents.reGroupName} = ${actorName} AND ${ransomwareEvents.victimName} = ${evt.victimName}`).limit(1);
      if (!existingRe) {
        await db.insert(ransomwareEvents).values({
          reGroupName: actorName,
          victimName: evt.victimName,
          reCountry: evt.victimCountry,
          reSector: evt.victimSector,
          reDescription: evt.description,
          publishedAt: new Date(evt.eventDate).toISOString(),
          reSource: "dailydarkweb_osint",
          verified: 1
        });
        breachEventsInserted++;
      }
    }
  }
  console.log(`[DailyDarkWeb] Actor sync: ${actorsInserted} new actors, ${eventsInserted} new events, ${breachEventsInserted} breach events`);
  return { actors: actorsInserted, events: eventsInserted, breachEvents: breachEventsInserted };
}
async function syncDailyDarkWebFeed() {
  const fulcrumsec = await syncFulcrumsec();
  const actors = await syncDailyDarkWebActors();
  return { fulcrumsec, actors, source: DAILYDARKWEB_SOURCE };
}
var DAILYDARKWEB_SOURCE, FULCRUMSEC_ACTOR, FULCRUMSEC_IOCS, FULCRUMSEC_EVENTS, DAILYDARKWEB_ACTORS, DAILYDARKWEB_EVENTS;
var init_dailydarkweb_feed = __esm({
  "server/lib/dailydarkweb-feed.ts"() {
    init_db();
    init_schema();
    DAILYDARKWEB_SOURCE = {
      id: "dailydarkweb",
      name: "Daily Dark Web",
      url: "https://dailydarkweb.net",
      description: "Independent darkweb news and threat intelligence aggregator covering ransomware, data breaches, unauthorized access sales, and cyber attacks. Provides timely reporting on threat actor claims, victim disclosures, and underground marketplace activity.",
      categories: [
        "ransomware-news",
        "data-breaches",
        "cyber-attacks",
        "unauthorized-accesses",
        "darkweb-news"
      ],
      reliability: "B",
      confidence: 75,
      addedDate: "2026-03-04"
    };
    FULCRUMSEC_ACTOR = {
      actorId: "fulcrumsec",
      name: "FULCRUMSEC",
      aliases: ["The Threat Thespians", "FulcrumSec"],
      actorType: "cybercrime",
      origin: "Unknown",
      description: "FULCRUMSEC (also known as The Threat Thespians) is a data extortion group first observed in September 2025. They operate a classic steal-then-threaten model, exfiltrating data and demanding payment to prevent publication. They maintain a dedicated Dark Web Data Leak Site (DLS), underground forum presence, and Telegram channel. Their extortion methods include blackmail, data auctions, direct extortion, double extortion, free data leaks, and detailed kill chain write-ups that expose victim security failures. Notable for targeting cloud infrastructure (AWS) and exploiting web application vulnerabilities.",
      motivation: "financial",
      firstSeen: "2025-09",
      lastActive: "2026-03",
      threatLevel: "high",
      sophistication: "advanced",
      targetSectors: ["Legal", "Technology", "Electronics", "FinTech", "Military/Industrial", "Information Services"],
      targetRegions: ["US", "AU", "UK"],
      techniques: [
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
        { id: "T1078", name: "Valid Accounts", tactic: "defense-evasion" },
        { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "defense-evasion" },
        { id: "T1530", name: "Data from Cloud Storage Object", tactic: "collection" },
        { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "exfiltration" },
        { id: "T1552.005", name: "Unsecured Credentials: Cloud Instance Metadata API", tactic: "credential-access" },
        { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "credential-access" },
        { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "discovery" },
        { id: "T1619", name: "Cloud Storage Object Discovery", tactic: "discovery" },
        { id: "T1087.004", name: "Account Discovery: Cloud Account", tactic: "discovery" }
      ],
      tools: ["React2Shell", "AWS CLI", "Custom exfiltration tooling"],
      malware: [],
      activityTimeline: [
        { date: "2025-09", event: "First observed activity; Avnet breach (850GB exfiltrated)", source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
        { date: "2025-10", event: "youX (FinTech, Australia) breach \u2014 300GB exfiltrated", source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
        { date: "2025-11", event: "Raptor Supplies (Military/Industrial, UK) breach", source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
        { date: "2026-03", event: "LexisNexis (RELX Group) breach \u2014 2.04GB structured data, 3.9M records, AWS infrastructure compromised", source: "https://dailydarkweb.net/lexisnexis-investigates-massive-data-breach-by-fulcrumsec/" }
      ],
      confidence: 85,
      sources: [
        { url: "https://dailydarkweb.net/lexisnexis-investigates-massive-data-breach-by-fulcrumsec/", title: "LexisNexis Investigates Massive Data Breach by FULCRUMSEC", publisher: "Daily Dark Web", date: "2026-03-03" },
        { url: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec", title: "FulcrumSec Ransomware Tracker", publisher: "WatchGuard", date: "2026-03-04" },
        { url: "https://x.com/KrakenLabs_Team/status/2029114296475451696", title: "KrakenLabs FULCRUMSEC Analysis", publisher: "KrakenLabs (Outpost24)", date: "2026-03-04" }
      ]
    };
    FULCRUMSEC_IOCS = [
      { actorId: "fulcrumsec", type: "domain", value: "fulcrumsec.net", description: "FULCRUMSEC clearnet website", firstSeen: "2025-09", confidence: 95, source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
      { actorId: "fulcrumsec", type: "url", value: "http://gsgot6tua7ffammwdv6vpxkog32b4z7qivtqkxz55afq2hkt2o24w5yd.onion", description: "FULCRUMSEC TOR data leak site (DLS)", firstSeen: "2025-09", confidence: 95, source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
      { actorId: "fulcrumsec", type: "email", value: "fulcrumsec@tuta.io", description: "FULCRUMSEC primary contact email (Tutanota)", firstSeen: "2025-09", confidence: 90, source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
      { actorId: "fulcrumsec", type: "email", value: "threatspians@fulcrumsec.net", description: "FULCRUMSEC secondary contact email", firstSeen: "2025-09", confidence: 90, source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" },
      { actorId: "fulcrumsec", type: "url", value: "https://t.me/fulcrumsec", description: "FULCRUMSEC Telegram channel", firstSeen: "2025-09", confidence: 90, source: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec" }
    ];
    FULCRUMSEC_EVENTS = [
      {
        actorId: "fulcrumsec",
        eventType: "data_leak",
        title: "FULCRUMSEC claims massive LexisNexis data breach \u2014 3.9M records, AWS infrastructure compromised",
        description: "FULCRUMSEC published a detailed kill chain write-up claiming to have breached LexisNexis (RELX Group) by exploiting a vulnerable React application container role in AWS. The group claims to have exfiltrated 2.04 GB of structured data including 536 Redshift tables, 430+ VPC database tables, 53 AWS Secrets Manager secrets in plaintext, 3.9 million Enterprise Data Warehouse records, ~400,000 cloud user profiles, 118 government user accounts (federal judges, DOJ attorneys, SEC staff), 21,042 customer account records, and 45 employee password hashes. The breach reportedly exploited the React2Shell vulnerability to gain initial access through a container role, then pivoted through AWS infrastructure. Claim has NOT been independently verified.",
        severity: "critical",
        victimName: "LexisNexis (RELX Group)",
        victimSector: "Legal/Information Services",
        victimCountry: "United States",
        mitreTechniques: ["T1190", "T1078.004", "T1530", "T1537", "T1552.005", "T1552.001", "T1580", "T1619"],
        iocs: [{ type: "domain", value: "fulcrumsec.net" }, { type: "url", value: "http://gsgot6tua7ffammwdv6vpxkog32b4z7qivtqkxz55afq2hkt2o24w5yd.onion" }],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net/lexisnexis-investigates-massive-data-breach-by-fulcrumsec/",
        confidence: 75,
        eventDate: "2026-03-03"
      },
      {
        actorId: "fulcrumsec",
        eventType: "attack",
        title: "FULCRUMSEC breaches Avnet \u2014 850GB exfiltrated from electronics distributor",
        description: "FULCRUMSEC claimed its first major victim, Avnet (a Fortune 500 electronics distributor), exfiltrating approximately 850GB of data.",
        severity: "high",
        victimName: "Avnet",
        victimSector: "Electronics/Technology",
        victimCountry: "United States",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "WatchGuard Ransomware Tracker",
        sourceUrl: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec",
        confidence: 80,
        eventDate: "2025-09-26"
      },
      {
        actorId: "fulcrumsec",
        eventType: "attack",
        title: "FULCRUMSEC breaches youX \u2014 300GB exfiltrated from Australian FinTech",
        description: "FULCRUMSEC targeted youX, an Australian FinTech company, exfiltrating approximately 300GB of data.",
        severity: "high",
        victimName: "youX",
        victimSector: "FinTech",
        victimCountry: "Australia",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "WatchGuard Ransomware Tracker",
        sourceUrl: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec",
        confidence: 80,
        eventDate: "2025-10-15"
      },
      {
        actorId: "fulcrumsec",
        eventType: "attack",
        title: "FULCRUMSEC breaches Raptor Supplies \u2014 UK military/industrial supplier",
        description: "FULCRUMSEC targeted Raptor Supplies, a UK-based military and industrial supplier.",
        severity: "high",
        victimName: "Raptor Supplies",
        victimSector: "Military/Industrial",
        victimCountry: "United Kingdom",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "WatchGuard Ransomware Tracker",
        sourceUrl: "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/fulcrumsec",
        confidence: 80,
        eventDate: "2025-11-15"
      }
    ];
    DAILYDARKWEB_ACTORS = [
      {
        actorId: "ddw-vect",
        name: "Vect",
        aliases: ["Vect Ransomware"],
        actorType: "ransomware",
        origin: "Unknown",
        description: "Emerging ransomware group observed targeting energy sector infrastructure in South America. Claimed Verlat Energy (Peru, hydropower) as a victim in March 2026.",
        motivation: "financial",
        firstSeen: "2026-02",
        lastActive: "2026-03",
        threatLevel: "medium",
        sophistication: "intermediate",
        targetSectors: ["Energy", "Utilities"],
        targetRegions: ["PE", "LATAM"],
        techniques: [{ id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" }],
        tools: [],
        malware: ["Vect ransomware"],
        activityTimeline: [{ date: "2026-03-04", event: "Claimed Verlat Energy (Peru, hydropower) as victim", source: "https://dailydarkweb.net (ransomware-news)" }],
        confidence: 65,
        sources: [{ url: "https://dailydarkweb.net", title: "Vect ransomware claims Verlat Energy", publisher: "Daily Dark Web", date: "2026-03-04" }]
      },
      {
        actorId: "ddw-ailock",
        name: "AiLock",
        aliases: ["AiLock Ransomware"],
        actorType: "ransomware",
        origin: "Unknown",
        description: "Ransomware group observed targeting legal sector and multiple global companies. Claimed Aaronson Rappaport & Demanor and multiple other organizations as victims in March 2026.",
        motivation: "financial",
        firstSeen: "2026-02",
        lastActive: "2026-03",
        threatLevel: "medium",
        sophistication: "intermediate",
        targetSectors: ["Legal", "Multiple"],
        targetRegions: ["US", "Global"],
        techniques: [{ id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" }],
        tools: [],
        malware: ["AiLock ransomware"],
        activityTimeline: [{ date: "2026-03-03", event: "Claimed Aaronson Rappaport & Demanor + multiple global companies as victims", source: "https://dailydarkweb.net (ransomware-news)" }],
        confidence: 65,
        sources: [{ url: "https://dailydarkweb.net", title: "AiLock ransomware claims multiple victims", publisher: "Daily Dark Web", date: "2026-03-03" }]
      },
      {
        actorId: "ddw-handala",
        name: "Handala Hack Team",
        aliases: ["Handala", "Handala Hackers"],
        actorType: "hacktivist",
        origin: "Iran (suspected)",
        description: "Pro-Palestinian hacktivist group conducting data breaches and disruptive attacks primarily targeting Israeli organizations and Middle Eastern energy companies. Named after the Handala character, a symbol of Palestinian resistance.",
        motivation: "ideological",
        firstSeen: "2024-01",
        lastActive: "2026-03",
        threatLevel: "high",
        sophistication: "advanced",
        targetSectors: ["Energy", "Finance", "Government", "Technology"],
        targetRegions: ["IL", "AE", "SA", "ME"],
        techniques: [
          { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
          { id: "T1530", name: "Data from Cloud Storage Object", tactic: "collection" },
          { id: "T1491", name: "Defacement", tactic: "impact" },
          { id: "T1561", name: "Disk Wipe", tactic: "impact" }
        ],
        tools: ["Custom wipers", "Data exfiltration tools"],
        malware: [],
        activityTimeline: [
          { date: "2025-07-04", event: "Breached Nifloat Hatzuna Ltd. and Vynopsis (Israel)", source: "https://dailydarkweb.net (cyber-attacks)" },
          { date: "2025-10-10", event: "Major data breach of Delek Group (Israeli conglomerate)", source: "https://dailydarkweb.net (cyber-attacks)" },
          { date: "2026-03-03", event: "Claimed Sharjah National Oil and Israel Opportunity as victims", source: "https://dailydarkweb.net (ransomware-news)" }
        ],
        confidence: 80,
        sources: [
          { url: "https://dailydarkweb.net", title: "Handala Hack Team claims Sharjah National Oil", publisher: "Daily Dark Web", date: "2026-03-03" },
          { url: "https://dailydarkweb.net", title: "Handala Hack Team breaches Delek Group", publisher: "Daily Dark Web", date: "2025-10-10" },
          { url: "https://dailydarkweb.net", title: "Handala breaches Nifloat Hatzuna and Vynopsis", publisher: "Daily Dark Web", date: "2025-07-04" }
        ]
      },
      {
        actorId: "ddw-ruskinet",
        name: "RuskiNet Group",
        aliases: ["RuskiNet"],
        actorType: "hacktivist",
        origin: "Russia",
        description: "Pro-Russian hacktivist group targeting Israeli organizations. Claimed breach of Har Hevron Regional Council and 4 other Israeli organizations in June 2025.",
        motivation: "ideological",
        firstSeen: "2025-06",
        lastActive: "2025-06",
        threatLevel: "medium",
        sophistication: "intermediate",
        targetSectors: ["Government", "Municipal"],
        targetRegions: ["IL"],
        techniques: [
          { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
          { id: "T1530", name: "Data from Cloud Storage Object", tactic: "collection" }
        ],
        tools: [],
        malware: [],
        activityTimeline: [{ date: "2025-06-27", event: "Breached Har Hevron Regional Council + 4 Israeli organizations", source: "https://dailydarkweb.net (cyber-attacks)" }],
        confidence: 70,
        sources: [{ url: "https://dailydarkweb.net", title: "RuskiNet Group breaches Israeli organizations", publisher: "Daily Dark Web", date: "2025-06-27" }]
      }
    ];
    DAILYDARKWEB_EVENTS = [
      {
        actorId: "qilin",
        eventType: "attack",
        title: "Qilin claims 5 new victims: Vision Aero, ATS, Golden Clay, Outsourcia, Dr. Pizzoglio",
        description: "Qilin ransomware group added 5 new victims to their leak site across multiple sectors.",
        severity: "high",
        victimName: "Vision Aero, ATS, Golden Clay, Outsourcia, Dr. Pizzoglio",
        victimSector: "Multiple",
        victimCountry: "Multiple",
        mitreTechniques: ["T1486", "T1490"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-04"
      },
      {
        actorId: "dragonforce",
        eventType: "attack",
        title: "Dragonforce claims 3 new victims: New Generation Media, Lincoln Green, Bravo Electro",
        description: "Dragonforce ransomware group added 3 new victims to their leak site.",
        severity: "high",
        victimName: "New Generation Media, Lincoln Green, Bravo Electro",
        victimSector: "Media, Real Estate, Electronics",
        victimCountry: "Multiple",
        mitreTechniques: ["T1486", "T1490"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-04"
      },
      {
        actorId: "akira",
        eventType: "attack",
        title: "Akira claims ICAFe Companies / Southwest Air Equipment (Texas)",
        description: "Akira ransomware group claimed ICAFe Companies and Southwest Air Equipment in Texas as victims.",
        severity: "high",
        victimName: "ICAFe Companies / Southwest Air Equipment",
        victimSector: "Industrial Equipment",
        victimCountry: "United States",
        mitreTechniques: ["T1486", "T1490"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-04"
      },
      {
        actorId: "anubis",
        eventType: "attack",
        title: "Anubis ransomware claims Andal Law Group (Orange County)",
        description: "Anubis ransomware group claimed Andal Law Group, an Orange County personal injury law firm, as a victim.",
        severity: "medium",
        victimName: "Andal Law Group",
        victimSector: "Legal",
        victimCountry: "United States",
        mitreTechniques: ["T1486"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-03"
      },
      {
        actorId: "play",
        eventType: "attack",
        title: "Play ransomware claims Cabka, WCC, LRA, Kuker Group (US & Germany)",
        description: "Play ransomware group added 4 new victims across the US and Germany.",
        severity: "high",
        victimName: "Cabka, WCC, LRA, Kuker Group",
        victimSector: "Manufacturing, Multiple",
        victimCountry: "United States, Germany",
        mitreTechniques: ["T1486", "T1490"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-03"
      },
      {
        actorId: "rhysida",
        eventType: "attack",
        title: "Rhysida claims Southold Town Senior Services and Southold Police Department",
        description: "Rhysida ransomware group claimed Southold Town Senior Services and Southold Police Department as victims.",
        severity: "high",
        victimName: "Southold Town Senior Services, Southold Police Department",
        victimSector: "Government/Public Services",
        victimCountry: "United States",
        mitreTechniques: ["T1486", "T1490"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-02"
      },
      {
        actorId: "ddw-handala",
        eventType: "attack",
        title: "Handala Hack Team claims Sharjah National Oil and Israel Opportunity",
        description: "Handala Hack Team, a pro-Palestinian hacktivist group, claimed breaches of Sharjah National Oil Corporation and Israel Opportunity.",
        severity: "high",
        victimName: "Sharjah National Oil, Israel Opportunity",
        victimSector: "Energy, Finance",
        victimCountry: "UAE, Israel",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2026-03-03"
      },
      {
        actorId: "ddw-handala",
        eventType: "attack",
        title: "Handala Hack Team breaches Delek Group (major Israeli conglomerate)",
        description: "Handala Hack Team claimed a major data breach of Delek Group, one of Israel's largest conglomerates.",
        severity: "critical",
        victimName: "Delek Group",
        victimSector: "Energy/Conglomerate",
        victimCountry: "Israel",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 75,
        eventDate: "2025-10-10"
      },
      {
        actorId: "ddw-vect",
        eventType: "attack",
        title: "Vect ransomware claims Verlat Energy (Peru, hydropower)",
        description: "Emerging ransomware group Vect claimed Verlat Energy, a Peruvian hydropower company, as a victim.",
        severity: "medium",
        victimName: "Verlat Energy",
        victimSector: "Energy/Hydropower",
        victimCountry: "Peru",
        mitreTechniques: ["T1486"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 65,
        eventDate: "2026-03-04"
      },
      {
        actorId: "ddw-ailock",
        eventType: "attack",
        title: "AiLock ransomware claims Aaronson Rappaport & Demanor + multiple global companies",
        description: "AiLock ransomware group claimed multiple victims including Aaronson Rappaport & Demanor (a law firm).",
        severity: "high",
        victimName: "Aaronson Rappaport & Demanor",
        victimSector: "Legal",
        victimCountry: "United States",
        mitreTechniques: ["T1486"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 65,
        eventDate: "2026-03-03"
      },
      {
        actorId: "ddw-ruskinet",
        eventType: "attack",
        title: "RuskiNet Group breaches Har Hevron Regional Council + 4 Israeli organizations",
        description: "Pro-Russian hacktivist group RuskiNet claimed breaches of Har Hevron Regional Council and 4 other Israeli organizations.",
        severity: "high",
        victimName: "Har Hevron Regional Council",
        victimSector: "Government/Municipal",
        victimCountry: "Israel",
        mitreTechniques: ["T1190", "T1530"],
        iocs: [],
        source: "Daily Dark Web",
        sourceUrl: "https://dailydarkweb.net",
        confidence: 70,
        eventDate: "2025-06-27"
      }
    ];
  }
});
init_dailydarkweb_feed();
export {
  DAILYDARKWEB_SOURCE,
  syncDailyDarkWebActors,
  syncDailyDarkWebFeed,
  syncFulcrumsec
};
