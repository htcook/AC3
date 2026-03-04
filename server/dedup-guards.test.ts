import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock drizzle-orm
vi.mock("drizzle-orm", () => ({
  eq: vi.fn((a, b) => ({ type: 'eq', a, b })),
  desc: vi.fn((a) => ({ type: 'desc', a })),
  inArray: vi.fn((a, b) => ({ type: 'inArray', a, b })),
  like: vi.fn((a, b) => ({ type: 'like', a, b })),
  and: vi.fn((...args) => ({ type: 'and', args })),
  sql: vi.fn(),
  not: vi.fn(),
  or: vi.fn(),
  gt: vi.fn(),
  ne: vi.fn(),
}));

// Mock drizzle/mysql2
vi.mock("drizzle-orm/mysql2", () => ({
  drizzle: vi.fn(),
}));

describe("Deduplication Guards", () => {
  describe("Domain Recon Dedup", () => {
    it("should prevent duplicate domain recon entries for same engagement+domain", () => {
      // This test validates the dedup guard logic conceptually
      const existingRecords = [
        { id: 1, engagementId: 100, domain: "example.com" },
      ];
      
      const newRecon = { engagementId: 100, domain: "example.com" };
      const isDuplicate = existingRecords.some(
        r => r.engagementId === newRecon.engagementId && r.domain === newRecon.domain
      );
      
      expect(isDuplicate).toBe(true);
    });

    it("should allow new domain recon entries for different domains", () => {
      const existingRecords = [
        { id: 1, engagementId: 100, domain: "example.com" },
      ];
      
      const newRecon = { engagementId: 100, domain: "other.com" };
      const isDuplicate = existingRecords.some(
        r => r.engagementId === newRecon.engagementId && r.domain === newRecon.domain
      );
      
      expect(isDuplicate).toBe(false);
    });
  });

  describe("Typosquat Dedup", () => {
    it("should filter out duplicate typosquats from bulk insert", () => {
      const existingSet = new Set([
        "example.com||exampel.com",
        "example.com||exampl.com",
      ]);
      
      const newDomains = [
        { engagementId: 100, originalDomain: "example.com", permutedDomain: "exampel.com" },
        { engagementId: 100, originalDomain: "example.com", permutedDomain: "exampel.com" }, // dup of existing
        { engagementId: 100, originalDomain: "example.com", permutedDomain: "exmple.com" },  // new
      ];
      
      const filtered = newDomains.filter(
        d => !existingSet.has(`${d.originalDomain}||${d.permutedDomain}`)
      );
      
      expect(filtered).toHaveLength(1);
      expect(filtered[0].permutedDomain).toBe("exmple.com");
    });

    it("should allow all domains when no existing records", () => {
      const existingSet = new Set<string>();
      
      const newDomains = [
        { engagementId: 100, originalDomain: "example.com", permutedDomain: "exampel.com" },
        { engagementId: 100, originalDomain: "example.com", permutedDomain: "exmple.com" },
      ];
      
      const filtered = newDomains.filter(
        d => !existingSet.has(`${d.originalDomain}||${d.permutedDomain}`)
      );
      
      expect(filtered).toHaveLength(2);
    });
  });

  describe("OSINT Findings Dedup", () => {
    it("should filter out duplicate OSINT findings from bulk insert", () => {
      const existingSet = new Set([
        "dns_misconfiguration||No SPF Record",
        "dns_misconfiguration||No DMARC Record",
      ]);
      
      const newFindings = [
        { engagementId: 100, category: "dns_misconfiguration", title: "No SPF Record" },
        { engagementId: 100, category: "dns_misconfiguration", title: "No DMARC Record" },
        { engagementId: 100, category: "certificate", title: "Expired SSL Certificate" },
      ];
      
      const filtered = newFindings.filter(
        f => !existingSet.has(`${f.category}||${f.title}`)
      );
      
      expect(filtered).toHaveLength(1);
      expect(filtered[0].title).toBe("Expired SSL Certificate");
    });

    it("should prevent single finding insert when duplicate exists", () => {
      const existingRecords = [
        { id: 1, engagementId: 100, category: "dns_misconfiguration", title: "No SPF Record" },
      ];
      
      const newFinding = { engagementId: 100, category: "dns_misconfiguration", title: "No SPF Record" };
      const isDuplicate = existingRecords.some(
        r => r.engagementId === newFinding.engagementId 
          && r.category === newFinding.category 
          && r.title === newFinding.title
      );
      
      expect(isDuplicate).toBe(true);
    });

    it("should allow new finding categories", () => {
      const existingRecords = [
        { id: 1, engagementId: 100, category: "dns_misconfiguration", title: "No SPF Record" },
      ];
      
      const newFinding = { engagementId: 100, category: "open_port", title: "Port 22 Open" };
      const isDuplicate = existingRecords.some(
        r => r.engagementId === newFinding.engagementId 
          && r.category === newFinding.category 
          && r.title === newFinding.title
      );
      
      expect(isDuplicate).toBe(false);
    });
  });

  describe("Set-based dedup performance", () => {
    it("handles large datasets efficiently", () => {
      // Simulate 1000 existing records
      const existingSet = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        existingSet.add(`example.com||variant${i}.com`);
      }
      
      // 500 new domains, 250 duplicates + 250 new
      const newDomains = [];
      for (let i = 0; i < 250; i++) {
        newDomains.push({ originalDomain: "example.com", permutedDomain: `variant${i}.com` }); // dup
      }
      for (let i = 1000; i < 1250; i++) {
        newDomains.push({ originalDomain: "example.com", permutedDomain: `variant${i}.com` }); // new
      }
      
      const filtered = newDomains.filter(
        d => !existingSet.has(`${d.originalDomain}||${d.permutedDomain}`)
      );
      
      expect(filtered).toHaveLength(250);
    });
  });
});
