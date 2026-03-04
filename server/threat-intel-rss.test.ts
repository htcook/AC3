/**
 * Tests for Multi-Source Threat Intel RSS Ingestion Engine
 *
 * Tests the RSS parser, event classification, threat actor extraction,
 * CVE extraction, feed catalog, and deduplication logic.
 */

import { describe, it, expect } from "vitest";
import {
  parseRSSXml,
  extractThreatActor,
  classifyForUnderground,
  classifyIncidentType,
  assessSeverity,
  extractCVEs,
  makeSourceId,
  getFeedCatalog,
  THREAT_INTEL_FEEDS,
} from "./lib/threat-intel-rss";
import type { RSSItem, FeedSource } from "./lib/threat-intel-rss";

// ─── Helper: Create a mock RSS item ─────────────────────────────────

function mockItem(overrides: Partial<RSSItem> = {}): RSSItem {
  return {
    title: "Test Article Title",
    link: "https://example.com/article-1",
    pubDate: "Mon, 03 Mar 2025 12:00:00 +0000",
    categories: ["Ransomware News"],
    description: "A test article about cybersecurity.",
    contentEncoded: "",
    creator: "admin",
    guid: "https://example.com/?p=123",
    ...overrides,
  };
}

function mockFeed(overrides: Partial<FeedSource> = {}): FeedSource {
  return {
    id: "test-feed",
    name: "Test Feed",
    url: "https://example.com/feed/",
    tier: 1,
    category: "general",
    targets: ["threat_group_events", "underground_intel"],
    enabled: true,
    ...overrides,
  };
}

// ─── Feed Catalog Tests ─────────────────────────────────────────────

describe("Feed Catalog", () => {
  it("should have at least 15 total feeds", () => {
    expect(THREAT_INTEL_FEEDS.length).toBeGreaterThanOrEqual(15);
  });

  it("should have feeds across all 4 tiers", () => {
    const tiers = new Set(THREAT_INTEL_FEEDS.map(f => f.tier));
    expect(tiers.has(1)).toBe(true);
    expect(tiers.has(2)).toBe(true);
    expect(tiers.has(3)).toBe(true);
    expect(tiers.has(4)).toBe(true);
  });

  it("should have dailydarkweb.net as a Tier 1 feed", () => {
    const ddw = THREAT_INTEL_FEEDS.find(f => f.id === "dailydarkweb-main");
    expect(ddw).toBeDefined();
    expect(ddw!.tier).toBe(1);
    expect(ddw!.enabled).toBe(true);
    expect(ddw!.targets).toContain("threat_group_events");
    expect(ddw!.targets).toContain("ransomware_events");
    expect(ddw!.targets).toContain("underground_intel");
    expect(ddw!.targets).toContain("incident_reports");
  });

  it("should have ransomware.live as a Tier 1 feed", () => {
    const rl = THREAT_INTEL_FEEDS.find(f => f.id === "ransomware-live");
    expect(rl).toBeDefined();
    expect(rl!.tier).toBe(1);
    expect(rl!.targets).toContain("ransomware_events");
  });

  it("should have BleepingComputer as a Tier 1 feed", () => {
    const bc = THREAT_INTEL_FEEDS.find(f => f.id === "bleepingcomputer");
    expect(bc).toBeDefined();
    expect(bc!.tier).toBe(1);
  });

  it("should have CISA as a Tier 2 feed", () => {
    const cisa = THREAT_INTEL_FEEDS.find(f => f.id === "cisa-alerts");
    expect(cisa).toBeDefined();
    expect(cisa!.tier).toBe(2);
    expect(cisa!.category).toBe("zero_day");
  });

  it("should have vendor research feeds in Tier 3", () => {
    const tier3 = THREAT_INTEL_FEEDS.filter(f => f.tier === 3);
    expect(tier3.length).toBeGreaterThanOrEqual(3);
    const names = tier3.map(f => f.name);
    expect(names.some(n => n.includes("Mandiant"))).toBe(true);
    expect(names.some(n => n.includes("Unit 42"))).toBe(true);
  });

  it("should return enabled and disabled feeds from getFeedCatalog", () => {
    const catalog = getFeedCatalog();
    expect(catalog.enabled.length).toBeGreaterThan(0);
    expect(catalog.disabled.length).toBeGreaterThanOrEqual(0);
    expect(catalog.enabled.length + catalog.disabled.length).toBe(THREAT_INTEL_FEEDS.length);
  });

  it("should have unique feed IDs", () => {
    const ids = THREAT_INTEL_FEEDS.map(f => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should have valid URLs for all feeds", () => {
    for (const feed of THREAT_INTEL_FEEDS) {
      expect(feed.url).toMatch(/^https?:\/\//);
    }
  });
});

// ─── RSS Parser Tests ───────────────────────────────────────────────

describe("RSS Parser", () => {
  it("should parse standard RSS 2.0 XML", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <lastBuildDate>Mon, 03 Mar 2025 12:00:00 +0000</lastBuildDate>
    <item>
      <title>LockBit Ransomware Targets Healthcare</title>
      <link>https://example.com/article-1</link>
      <pubDate>Mon, 03 Mar 2025 10:00:00 +0000</pubDate>
      <category>Ransomware News</category>
      <description>LockBit claims new healthcare victims.</description>
      <guid>https://example.com/?p=1</guid>
    </item>
    <item>
      <title>New Zero-Day in Chrome</title>
      <link>https://example.com/article-2</link>
      <pubDate>Sun, 02 Mar 2025 08:00:00 +0000</pubDate>
      <category>Zero-Day</category>
      <description>CVE-2025-1234 discovered in Chrome.</description>
      <guid>https://example.com/?p=2</guid>
    </item>
  </channel>
</rss>`;

    const feed = parseRSSXml(xml);
    expect(feed.title).toBe("Test Feed");
    expect(feed.items.length).toBe(2);
    expect(feed.items[0].title).toBe("LockBit Ransomware Targets Healthcare");
    expect(feed.items[0].link).toBe("https://example.com/article-1");
    expect(feed.items[0].categories).toContain("Ransomware News");
    expect(feed.items[1].title).toBe("New Zero-Day in Chrome");
  });

  it("should parse CDATA-wrapped content", () => {
    const xml = `<rss><channel><title>Test</title>
<item>
  <title><![CDATA[Akira Ransomware: New Variant Discovered]]></title>
  <link>https://example.com/akira</link>
  <pubDate>Mon, 03 Mar 2025 10:00:00 +0000</pubDate>
  <description><![CDATA[<p>Akira has released a new variant targeting Linux.</p>]]></description>
</item>
</channel></rss>`;

    const feed = parseRSSXml(xml);
    expect(feed.items.length).toBe(1);
    expect(feed.items[0].title).toBe("Akira Ransomware: New Variant Discovered");
    expect(feed.items[0].description).toContain("Akira has released");
  });

  it("should handle empty feeds gracefully", () => {
    const xml = `<rss><channel><title>Empty</title></channel></rss>`;
    const feed = parseRSSXml(xml);
    expect(feed.title).toBe("Empty");
    expect(feed.items).toEqual([]);
  });

  it("should parse Atom feeds", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>CISA Advisories</title>
  <entry>
    <title>Critical Vulnerability in Fortinet</title>
    <link href="https://cisa.gov/advisory-1" rel="alternate"/>
    <published>2025-03-03T10:00:00Z</published>
    <summary>CISA warns of critical Fortinet vulnerability.</summary>
    <id>https://cisa.gov/advisory-1</id>
  </entry>
</feed>`;

    const feed = parseRSSXml(xml);
    expect(feed.title).toBe("CISA Advisories");
    expect(feed.items.length).toBe(1);
    expect(feed.items[0].title).toBe("Critical Vulnerability in Fortinet");
    expect(feed.items[0].link).toBe("https://cisa.gov/advisory-1");
  });
});

// ─── Threat Actor Extraction Tests ──────────────────────────────────

describe("Threat Actor Extraction", () => {
  it("should extract known ransomware groups from titles", () => {
    expect(extractThreatActor(mockItem({ title: "LockBit Claims New Victim in Healthcare" }))).toBe("LockBit");
    expect(extractThreatActor(mockItem({ title: "Akira Ransomware Targets Manufacturing" }))).toBe("Akira");
    expect(extractThreatActor(mockItem({ title: "FULCRUMSEC Breaches LexisNexis" }))).toBe("FULCRUMSEC");
    expect(extractThreatActor(mockItem({ title: "Play Ransomware Claims City Government" }))).toBe("Play");
  });

  it("should extract APT groups from titles", () => {
    expect(extractThreatActor(mockItem({ title: "APT28 Targets European Government" }))).toBe("APT28");
    expect(extractThreatActor(mockItem({ title: "Lazarus Group Deploys New Malware" }))).toBe("Lazarus");
    expect(extractThreatActor(mockItem({ title: "Volt Typhoon Compromises US Infrastructure" }))).toBe("Volt Typhoon");
  });

  it("should extract actors from categories", () => {
    expect(extractThreatActor(mockItem({
      title: "New Ransomware Attack",
      categories: ["Ransomware News", "Qilin"],
    }))).toBe("Qilin");
  });

  it("should return null for articles without identifiable actors", () => {
    expect(extractThreatActor(mockItem({
      title: "Best Practices for Cybersecurity in 2025",
      categories: ["General"],
    }))).toBeNull();
  });

  it("should handle case-insensitive matching", () => {
    expect(extractThreatActor(mockItem({ title: "lockbit attacks hospital" }))).toBe("LockBit");
    expect(extractThreatActor(mockItem({ title: "BLACKCAT ransomware update" }))).toBe("BlackCat");
  });
});

// ─── Event Classification Tests ─────────────────────────────────────

describe("Event Classification", () => {
  it("should classify ransomware events", () => {
    const item = mockItem({ title: "LockBit Ransomware Claims New Victim", categories: ["Ransomware News"] });
    expect(classifyForUnderground(item, mockFeed({ category: "ransomware" }))).toBe("ransomware");
  });

  it("should classify credential events", () => {
    const item = mockItem({ title: "Massive Credential Leak Discovered", description: "Password dump found on dark web" });
    expect(classifyForUnderground(item, mockFeed())).toBe("credential");
  });

  it("should classify malware events", () => {
    const item = mockItem({ title: "New Trojan Targets Banking Sector", description: "Backdoor malware discovered" });
    expect(classifyForUnderground(item, mockFeed())).toBe("malware");
  });

  it("should classify exploit events", () => {
    const item = mockItem({ title: "CVE-2025-1234 Zero-Day Exploit", description: "Zero-day vulnerability actively exploited" });
    expect(classifyForUnderground(item, mockFeed())).toBe("exploit");
  });

  it("should classify data leak events", () => {
    const item = mockItem({ title: "Major Data Breach at Corporation", description: "Data exfiltrated from servers" });
    expect(classifyForUnderground(item, mockFeed())).toBe("data_leak");
  });

  it("should classify phishing events", () => {
    const item = mockItem({ title: "Phishing Campaign Targets Banks", description: "Social engineering attack" });
    expect(classifyForUnderground(item, mockFeed())).toBe("phishing");
  });

  it("should fall back to feed category", () => {
    const item = mockItem({ title: "Generic Article", description: "Nothing specific" });
    expect(classifyForUnderground(item, mockFeed({ category: "ransomware" }))).toBe("ransomware");
    expect(classifyForUnderground(item, mockFeed({ category: "breach" }))).toBe("data_leak");
  });
});

// ─── Incident Type Classification ───────────────────────────────────

describe("Incident Type Classification", () => {
  it("should classify ransomware incidents", () => {
    expect(classifyIncidentType(mockItem({ title: "Ransomware Attack on Hospital" }))).toBe("ransomware");
  });

  it("should classify APT incidents", () => {
    expect(classifyIncidentType(mockItem({ title: "Nation-state espionage campaign" }))).toBe("apt");
  });

  it("should classify supply chain incidents", () => {
    expect(classifyIncidentType(mockItem({ title: "Supply chain attack compromises vendors" }))).toBe("supply_chain");
  });

  it("should classify zero-day incidents", () => {
    expect(classifyIncidentType(mockItem({ title: "CVE-2025-1234 zero-day exploited" }))).toBe("zero_day");
  });

  it("should classify data breach incidents", () => {
    expect(classifyIncidentType(mockItem({ title: "Massive data breach exposes millions" }))).toBe("data_breach");
  });
});

// ─── Severity Assessment Tests ──────────────────────────────────────

describe("Severity Assessment", () => {
  it("should rate government targets as critical", () => {
    expect(assessSeverity(mockItem({ title: "Attack on Government Agency" }))).toBe("critical");
    expect(assessSeverity(mockItem({ title: "Healthcare System Breached" }))).toBe("critical");
    expect(assessSeverity(mockItem({ title: "Military Data Exposed" }))).toBe("critical");
  });

  it("should rate ransomware and data breaches as high", () => {
    expect(assessSeverity(mockItem({ title: "Ransomware Claims New Victim" }))).toBe("high");
    expect(assessSeverity(mockItem({ title: "Database of 10 Million Records Leaked" }))).toBe("high");
  });

  it("should rate credential and access events as medium", () => {
    expect(assessSeverity(mockItem({ title: "Unauthorized Access to Server" }))).toBe("medium");
    expect(assessSeverity(mockItem({ title: "Credentials Found on Dark Web" }))).toBe("medium");
  });
});

// ─── CVE Extraction Tests ───────────────────────────────────────────

describe("CVE Extraction", () => {
  it("should extract CVE IDs from text", () => {
    const cves = extractCVEs("Vulnerability CVE-2025-1234 and CVE-2024-56789 discovered");
    expect(cves).toContain("CVE-2025-1234");
    expect(cves).toContain("CVE-2024-56789");
    expect(cves.length).toBe(2);
  });

  it("should deduplicate CVE IDs", () => {
    const cves = extractCVEs("CVE-2025-1234 is related to CVE-2025-1234");
    expect(cves.length).toBe(1);
  });

  it("should return empty array when no CVEs found", () => {
    expect(extractCVEs("No vulnerabilities mentioned here")).toEqual([]);
  });

  it("should handle case-insensitive CVE patterns", () => {
    const cves = extractCVEs("cve-2025-1234 is critical");
    expect(cves).toContain("CVE-2025-1234");
  });
});

// ─── Source ID / Deduplication Tests ────────────────────────────────

describe("Source ID Generation", () => {
  it("should generate deterministic IDs for the same item", () => {
    const item = mockItem();
    const id1 = makeSourceId("test-feed", item);
    const id2 = makeSourceId("test-feed", item);
    expect(id1).toBe(id2);
  });

  it("should generate different IDs for different feeds", () => {
    const item = mockItem();
    const id1 = makeSourceId("feed-a", item);
    const id2 = makeSourceId("feed-b", item);
    expect(id1).not.toBe(id2);
  });

  it("should generate different IDs for different items", () => {
    const item1 = mockItem({ guid: "guid-1" });
    const item2 = mockItem({ guid: "guid-2" });
    const id1 = makeSourceId("test-feed", item1);
    const id2 = makeSourceId("test-feed", item2);
    expect(id1).not.toBe(id2);
  });

  it("should use guid for deduplication when available", () => {
    const item = mockItem({ guid: "unique-guid-123" });
    const id = makeSourceId("test-feed", item);
    expect(id).toContain("test-feed:");
    expect(id.length).toBeGreaterThan(10);
  });
});
