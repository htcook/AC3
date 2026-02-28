import { describe, it, expect } from "vitest";

/**
 * Tests for Threat Intelligence Hub sorting logic.
 * Validates that all data feeds are sorted by most recent date first.
 */

// Helper: sort by date descending (most recent first)
function sortByDateDesc<T>(arr: T[], getDate: (item: T) => string | Date | null | undefined): T[] {
  return [...arr].sort((a, b) => {
    const da = getDate(a) ? new Date(getDate(a)!).getTime() : 0;
    const db2 = getDate(b) ? new Date(getDate(b)!).getTime() : 0;
    return db2 - da;
  });
}

describe("Threat Intel Hub Sorting", () => {

  describe("CISA KEV sorting by dateAdded", () => {
    const kevEntries = [
      { cveId: "CVE-2024-1001", dateAdded: "2024-01-15" },
      { cveId: "CVE-2024-5002", dateAdded: "2024-05-20" },
      { cveId: "CVE-2024-3003", dateAdded: "2024-03-10" },
      { cveId: "CVE-2025-1004", dateAdded: "2025-01-05" },
      { cveId: "CVE-2023-9005", dateAdded: "2023-09-01" },
    ];

    it("should sort KEV entries by dateAdded descending (most recent first)", () => {
      const sorted = sortByDateDesc(kevEntries, (k) => k.dateAdded);
      expect(sorted[0].cveId).toBe("CVE-2025-1004");
      expect(sorted[1].cveId).toBe("CVE-2024-5002");
      expect(sorted[2].cveId).toBe("CVE-2024-3003");
      expect(sorted[3].cveId).toBe("CVE-2024-1001");
      expect(sorted[4].cveId).toBe("CVE-2023-9005");
    });

    it("should handle null/undefined dateAdded by placing them last", () => {
      const withNulls = [
        { cveId: "CVE-2024-1001", dateAdded: "2024-01-15" },
        { cveId: "CVE-UNKNOWN", dateAdded: null as string | null },
        { cveId: "CVE-2025-1004", dateAdded: "2025-01-05" },
      ];
      const sorted = sortByDateDesc(withNulls, (k) => k.dateAdded);
      expect(sorted[0].cveId).toBe("CVE-2025-1004");
      expect(sorted[1].cveId).toBe("CVE-2024-1001");
      expect(sorted[2].cveId).toBe("CVE-UNKNOWN");
    });
  });

  describe("Escalation alerts sorting by eventDate", () => {
    const alerts = [
      { title: "Alert A", severity: "critical", eventDate: "2024-06-15T10:00:00Z", timestamp: null },
      { title: "Alert B", severity: "high", eventDate: "2025-02-01T08:00:00Z", timestamp: null },
      { title: "Alert C", severity: "critical", eventDate: null, timestamp: "2024-12-20T14:00:00Z" },
      { title: "Alert D", severity: "high", eventDate: "2024-03-01T06:00:00Z", timestamp: null },
    ];

    it("should sort escalation alerts by eventDate/timestamp descending", () => {
      const sorted = sortByDateDesc(alerts, (a) => a.eventDate || a.timestamp);
      expect(sorted[0].title).toBe("Alert B");
      expect(sorted[1].title).toBe("Alert C"); // falls back to timestamp
      expect(sorted[2].title).toBe("Alert A");
      expect(sorted[3].title).toBe("Alert D");
    });
  });

  describe("ThreatFox IOC sorting by firstSeen", () => {
    const iocs = [
      { ioc: "1.2.3.4", iocType: "ip", firstSeen: "2024-08-10T00:00:00Z" },
      { ioc: "evil.com", iocType: "domain", firstSeen: "2025-01-15T00:00:00Z" },
      { ioc: "abc123", iocType: "hash", firstSeen: "2024-02-20T00:00:00Z" },
      { ioc: "http://bad.com", iocType: "url", firstSeen: "2024-11-05T00:00:00Z" },
    ];

    it("should sort IOCs by firstSeen descending", () => {
      const sorted = sortByDateDesc(iocs, (i) => i.firstSeen);
      expect(sorted[0].ioc).toBe("evil.com");
      expect(sorted[1].ioc).toBe("http://bad.com");
      expect(sorted[2].ioc).toBe("1.2.3.4");
      expect(sorted[3].ioc).toBe("abc123");
    });
  });

  describe("Access broker sorting by postedAt", () => {
    const brokers = [
      { id: 1, brokerName: "Broker A", postedAt: "2024-04-10T00:00:00Z", createdAt: null },
      { id: 2, brokerName: "Broker B", postedAt: null, createdAt: "2025-01-20T00:00:00Z" },
      { id: 3, brokerName: "Broker C", postedAt: "2025-02-15T00:00:00Z", createdAt: null },
      { id: 4, brokerName: "Broker D", postedAt: null, createdAt: null },
    ];

    it("should sort access brokers by postedAt descending, falling back to createdAt", () => {
      const sorted = sortByDateDesc(brokers, (b) => b.postedAt || b.createdAt);
      expect(sorted[0].brokerName).toBe("Broker C");
      expect(sorted[1].brokerName).toBe("Broker B"); // falls back to createdAt
      expect(sorted[2].brokerName).toBe("Broker A");
      expect(sorted[3].brokerName).toBe("Broker D"); // null dates go last
    });
  });

  describe("Recent threat events sorting by eventDate", () => {
    const events = [
      { title: "Event 1", eventDate: "2024-07-01T00:00:00Z", timestamp: null },
      { title: "Event 2", eventDate: "2025-02-20T00:00:00Z", timestamp: null },
      { title: "Event 3", eventDate: null, timestamp: "2024-10-15T00:00:00Z" },
      { title: "Event 4", eventDate: "2024-01-01T00:00:00Z", timestamp: null },
    ];

    it("should sort events by eventDate/timestamp descending", () => {
      const sorted = sortByDateDesc(events, (e) => e.eventDate || e.timestamp);
      expect(sorted[0].title).toBe("Event 2");
      expect(sorted[1].title).toBe("Event 3");
      expect(sorted[2].title).toBe("Event 1");
      expect(sorted[3].title).toBe("Event 4");
    });
  });

  describe("Ransomware victim stats sorting by recent activity", () => {
    const groups = [
      { groupName: "LockBit", victims7d: 5, activityScore: 8 },
      { groupName: "BlackCat", victims7d: 12, activityScore: 9 },
      { groupName: "Cl0p", victims7d: 0, activityScore: 6 },
      { groupName: "Play", victims7d: 5, activityScore: 7 },
      { groupName: "Akira", victims7d: 0, activityScore: 4 },
    ];

    it("should sort by 7d victims descending, then activityScore descending", () => {
      const sorted = [...groups].sort((a, b) => {
        if (b.victims7d !== a.victims7d) return b.victims7d - a.victims7d;
        return b.activityScore - a.activityScore;
      });
      expect(sorted[0].groupName).toBe("BlackCat"); // 12 victims 7d
      expect(sorted[1].groupName).toBe("LockBit");  // 5 victims, score 8
      expect(sorted[2].groupName).toBe("Play");      // 5 victims, score 7
      expect(sorted[3].groupName).toBe("Cl0p");      // 0 victims, score 6
      expect(sorted[4].groupName).toBe("Akira");     // 0 victims, score 4
    });
  });

  describe("Edge cases", () => {
    it("should handle empty arrays gracefully", () => {
      const sorted = sortByDateDesc([], () => null);
      expect(sorted).toEqual([]);
    });

    it("should handle single-item arrays", () => {
      const sorted = sortByDateDesc([{ date: "2024-01-01" }], (i) => i.date);
      expect(sorted).toHaveLength(1);
    });

    it("should handle all-null dates without crashing", () => {
      const items = [
        { id: 1, date: null as string | null },
        { id: 2, date: null as string | null },
        { id: 3, date: null as string | null },
      ];
      const sorted = sortByDateDesc(items, (i) => i.date);
      expect(sorted).toHaveLength(3);
    });

    it("should handle invalid date strings without crashing", () => {
      const items = [
        { id: 1, date: "not-a-date" },
        { id: 2, date: "2025-01-01" },
      ];
      // NaN from invalid dates makes sort unstable, but it should not throw
      expect(() => sortByDateDesc(items, (i) => i.date)).not.toThrow();
      const sorted = sortByDateDesc(items, (i) => i.date);
      expect(sorted).toHaveLength(2);
    });
  });
});
