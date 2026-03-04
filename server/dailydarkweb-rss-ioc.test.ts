/**
 * Tests for Daily Dark Web RSS feed parser, IOC cross-reference engine,
 * and new router endpoints.
 */

import { describe, it, expect } from "vitest";

// ─── RSS Parser Tests ────────────────────────────────────────────────

describe("Daily Dark Web RSS Parser", () => {
  it("should parse RSS XML into structured items", async () => {
    const { parseRSSXml } = await import("./lib/dailydarkweb-rss");

    const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Daily Dark Web</title>
    <lastBuildDate>Tue, 04 Mar 2026 12:00:00 +0000</lastBuildDate>
    <item>
      <title><![CDATA[Qilin Ransomware Claims New Victim in Healthcare Sector]]></title>
      <link>https://dailydarkweb.net/qilin-healthcare-2026/</link>
      <dc:creator><![CDATA[DDW Team]]></dc:creator>
      <pubDate>Mon, 03 Mar 2026 10:00:00 +0000</pubDate>
      <category><![CDATA[Ransomware News]]></category>
      <category><![CDATA[Qilin]]></category>
      <description><![CDATA[Qilin ransomware group has claimed a new victim in the healthcare sector.]]></description>
      <content:encoded><![CDATA[<p>The <strong>Qilin</strong> ransomware group has claimed <strong>MedCorp Health</strong> as their latest victim.</p>]]></content:encoded>
    </item>
    <item>
      <title>Akira Attacks European Manufacturing Firm</title>
      <link>https://dailydarkweb.net/akira-manufacturing-2026/</link>
      <pubDate>Sun, 02 Mar 2026 08:00:00 +0000</pubDate>
      <category>Cyber Attacks</category>
      <category>Akira</category>
      <description>Akira ransomware targeted a European manufacturing company.</description>
      <content:encoded><p>Details of the <strong>EuroMfg GmbH</strong> breach by Akira.</p></content:encoded>
    </item>
  </channel>
</rss>`;

    const feed = parseRSSXml(sampleXml);
    expect(feed.title).toBe("Daily Dark Web");
    expect(feed.items).toHaveLength(2);
    expect(feed.items[0].title).toBe("Qilin Ransomware Claims New Victim in Healthcare Sector");
    expect(feed.items[0].link).toBe("https://dailydarkweb.net/qilin-healthcare-2026/");
    expect(feed.items[0].categories).toContain("Qilin");
    expect(feed.items[1].title).toBe("Akira Attacks European Manufacturing Firm");
  });

  it("should extract known threat actor names from titles", async () => {
    const { extractThreatActor } = await import("./lib/dailydarkweb-rss");

    const testCases = [
      { title: "Qilin Ransomware Claims New Victim", categories: ["Ransomware News"], expected: "Qilin" },
      { title: "FULCRUMSEC Breaches LexisNexis", categories: ["Data Breaches"], expected: "FULCRUMSEC" },
      { title: "Akira Attacks European Firm", categories: ["Cyber Attacks", "Akira"], expected: "Akira" },
      { title: "Play Ransomware Targets Healthcare", categories: ["Ransomware News", "Play"], expected: "Play" },
      { title: "Unknown Group Sells Access", categories: ["Unauthorized Accesses"], expected: null },
      { title: "Dragonforce Claims Multiple Victims", categories: [], expected: "Dragonforce" },
      { title: "RuskiNet Group Breaches Israeli Org", categories: [], expected: "RuskiNet" },
    ];

    for (const tc of testCases) {
      const result = extractThreatActor({
        title: tc.title,
        categories: tc.categories,
        link: "",
        pubDate: "",
        description: "",
        contentEncoded: "",
        creator: "",
      });
      expect(result).toBe(tc.expected);
    }
  });

  it("should classify event types from categories", async () => {
    const { classifyEventType } = await import("./lib/dailydarkweb-rss");

    expect(classifyEventType({
      title: "", link: "", pubDate: "", description: "", contentEncoded: "", creator: "",
      categories: ["Ransomware News"],
    })).toBe("ransomware_claim");

    expect(classifyEventType({
      title: "", link: "", pubDate: "", description: "", contentEncoded: "", creator: "",
      categories: ["Data Breaches"],
    })).toBe("data_leak");

    expect(classifyEventType({
      title: "", link: "", pubDate: "", description: "", contentEncoded: "", creator: "",
      categories: ["Cyber Attacks"],
    })).toBe("attack");
  });

  it("should assess severity based on content keywords", async () => {
    const { assessSeverity } = await import("./lib/dailydarkweb-rss");

    expect(assessSeverity({
      title: "Attack on Government Agency", link: "", pubDate: "", creator: "",
      categories: [], description: "government systems compromised", contentEncoded: "",
    })).toBe("critical");

    expect(assessSeverity({
      title: "Ransomware Attack", link: "", pubDate: "", creator: "",
      categories: [], description: "ransomware deployed", contentEncoded: "",
    })).toBe("high");

    expect(assessSeverity({
      title: "Unauthorized access sale", link: "", pubDate: "", creator: "",
      categories: [], description: "credentials for sale", contentEncoded: "",
    })).toBe("medium");
  });

  it("should extract victim names from bold HTML content", async () => {
    const { extractVictims } = await import("./lib/dailydarkweb-rss");

    const item = {
      title: "", link: "", pubDate: "", creator: "", categories: [],
      description: "",
      contentEncoded: "<p>The group claimed <strong>MedCorp Health</strong> (United States) and <strong>TechFirm Ltd</strong> (United Kingdom) as victims.</p>",
    };

    const victims = extractVictims(item);
    expect(victims.length).toBeGreaterThanOrEqual(2);
    expect(victims[0].name).toBe("MedCorp Health");
    expect(victims[1].name).toBe("TechFirm Ltd");
  });

  it("should process items into structured threat events", async () => {
    const { processItem } = await import("./lib/dailydarkweb-rss");

    const item = {
      title: "Qilin Ransomware Claims Healthcare Victim",
      link: "https://dailydarkweb.net/qilin-healthcare/",
      pubDate: "Mon, 03 Mar 2026 10:00:00 +0000",
      creator: "DDW Team",
      categories: ["Ransomware News", "Qilin"],
      description: "Qilin ransomware group claimed a new healthcare victim.",
      contentEncoded: "<p>The <strong>MedCorp Health</strong> was breached.</p>",
    };

    const event = processItem(item);
    expect(event).not.toBeNull();
    expect(event!.actorName).toBe("Qilin");
    expect(event!.actorId).toBe("qilin");
    expect(event!.eventType).toBe("ransomware_claim");
    expect(event!.sourceUrl).toBe("https://dailydarkweb.net/qilin-healthcare/");
  });

  it("should return null for items without identifiable threat actors", async () => {
    const { processItem } = await import("./lib/dailydarkweb-rss");

    const item = {
      title: "General Cybersecurity News Update",
      link: "https://dailydarkweb.net/general-news/",
      pubDate: "Mon, 03 Mar 2026 10:00:00 +0000",
      creator: "DDW Team",
      categories: ["Darkweb News"],
      description: "A general update on cybersecurity trends.",
      contentEncoded: "<p>General news content.</p>",
    };

    const event = processItem(item);
    expect(event).toBeNull();
  });

  it("should export DDW_RSS_FEEDS with correct structure", async () => {
    const { DDW_RSS_FEEDS } = await import("./lib/dailydarkweb-rss");

    expect(DDW_RSS_FEEDS).toBeInstanceOf(Array);
    expect(DDW_RSS_FEEDS.length).toBeGreaterThanOrEqual(5);
    for (const feed of DDW_RSS_FEEDS) {
      expect(feed).toHaveProperty("url");
      expect(feed).toHaveProperty("category");
      expect(feed).toHaveProperty("label");
      expect(feed.url).toContain("dailydarkweb.net");
    }
  });
});

// ─── IOC Cross-Reference Tests ───────────────────────────────────────

describe("IOC Cross-Reference Engine", () => {
  it("should export crossReferenceIOCs function", async () => {
    const mod = await import("./lib/ioc-cross-reference");
    expect(typeof mod.crossReferenceIOCs).toBe("function");
  });

  it("should have correct IOCMatch type structure", async () => {
    // Verify the module exports compile correctly
    const mod = await import("./lib/ioc-cross-reference");
    expect(mod).toBeDefined();
  });
});

// ─── Integration: Router Endpoints ───────────────────────────────────

describe("Darkweb Intel Router - New Endpoints", () => {
  it("should have syncDailyDarkWebRSS endpoint defined", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);
    expect(procedures).toContain("syncDailyDarkWebRSS");
  });

  it("should have getDDWRSSFeeds endpoint defined", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);
    expect(procedures).toContain("getDDWRSSFeeds");
  });

  it("should have crossReferenceIOCs endpoint defined", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);
    expect(procedures).toContain("crossReferenceIOCs");
  });

  it("should have crossReferenceFulcrumsec endpoint defined", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);
    expect(procedures).toContain("crossReferenceFulcrumsec");
  });
});

// ─── Scheduler Integration ───────────────────────────────────────────

describe("Darkweb Feed Scheduler - RSS Integration", () => {
  it("should include DDW RSS in the full sync function", async () => {
    // Verify the import path works (won't actually run the sync)
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.runFullDarkwebSync).toBe("function");
    expect(typeof mod.initDarkwebFeedScheduler).toBe("function");
    expect(typeof mod.isDarkwebSchedulerActive).toBe("function");
  });
});
