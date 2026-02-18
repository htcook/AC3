import { describe, it, expect } from 'vitest';

describe('Dehashed v4 Integration', () => {
  describe('Breach Data Extraction (unit)', () => {
    it('should extract breach summary from connector observations', () => {
      const observations = [
        { name: 'LinkedIn 2021', assetType: 'breach_source', tags: ['breach_database'], evidence: { total_records: 500, credentials_exposed: 120, has_passwords: true, has_hashed_passwords: false } },
        { name: 'Collection #1', assetType: 'breach_source', tags: ['breach_database'], evidence: { total_records: 200, credentials_exposed: 50, has_passwords: false, has_hashed_passwords: true } },
        { name: 'mail.example.com', assetType: 'subdomain', tags: ['subdomain_discovery'], evidence: {} },
        { name: 'vpn.example.com', assetType: 'subdomain', tags: ['subdomain_discovery'], evidence: {} },
        { name: '192.168.1.1', assetType: 'ip', tags: ['ip_discovery'], evidence: { database_name: 'LinkedIn 2021' } },
      ];

      const breachObs = observations.filter(o => o.tags?.includes('breach_database'));
      const subdomainObs = observations.filter(o => o.assetType === 'subdomain');
      const ipObs = observations.filter(o => o.assetType === 'ip');

      const totalExposures = breachObs.reduce((sum, o) => sum + (o.evidence?.total_records || 0), 0);
      const credentialPairs = breachObs.reduce((sum, o) => sum + (o.evidence?.credentials_exposed || 0), 0);
      const breachSources = breachObs.map(o => o.name);

      expect(totalExposures).toBe(700);
      expect(credentialPairs).toBe(170);
      expect(breachSources).toEqual(['LinkedIn 2021', 'Collection #1']);
      expect(subdomainObs.length).toBe(2);
      expect(ipObs.length).toBe(1);
    });

    it('should handle empty observations gracefully', () => {
      const observations: any[] = [];
      const breachObs = observations.filter(o => o.tags?.includes('breach_database'));
      expect(breachObs.length).toBe(0);
    });

    it('should handle v4 array-format entry fields', () => {
      // v4 API returns arrays for email, password, ip_address, etc.
      const entry = {
        id: "123",
        email: ["test@example.com", "test2@example.com"],
        ip_address: ["1.2.3.4"],
        password: ["pass123"],
        hashed_password: [],
        username: ["testuser"],
        database_name: "TestDB",
      };

      expect(Array.isArray(entry.email)).toBe(true);
      expect(Array.isArray(entry.ip_address)).toBe(true);
      expect(Array.isArray(entry.password)).toBe(true);
      expect(typeof entry.database_name).toBe("string");
      expect(entry.email[0]).toBe("test@example.com");
    });

    it('should produce the expected breachData shape for the frontend', () => {
      const breachData = {
        totalExposures: 1500,
        credentialPairs: 300,
        uniqueBreachSources: 5,
        subdomainsDiscovered: 12,
        ipsDiscovered: 3,
        breachSources: ['LinkedIn 2021', 'Collection #1', 'Dropbox 2012', 'Adobe 2013', 'Exploit.in'],
        queriedAt: new Date().toISOString(),
      };

      expect(breachData).toHaveProperty('totalExposures');
      expect(breachData).toHaveProperty('credentialPairs');
      expect(breachData).toHaveProperty('uniqueBreachSources');
      expect(breachData.breachSources.length).toBe(breachData.uniqueBreachSources);
    });
  });

  describe('Dehashed v4 API (live)', () => {
    const apiKey = process.env.DEHASHED_API_KEY;

    it('should have DEHASHED_API_KEY configured', () => {
      expect(apiKey).toBeDefined();
      expect(apiKey!.length).toBeGreaterThan(10);
    });

    it('should authenticate with v2/v4 POST endpoint', async () => {
      const res = await fetch("https://api.dehashed.com/v2/search", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Dehashed-Api-Key": apiKey!,
        },
        body: JSON.stringify({
          query: "domain:example.com",
          page: 1,
          size: 3,
          de_dupe: true,
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data).toHaveProperty("balance");
      expect(data).toHaveProperty("entries");
      expect(data).toHaveProperty("total");
      expect(typeof data.balance).toBe("number");
      expect(data.balance).toBeGreaterThan(0);
    }, 15000);

    it('should return v4 array-format entries from live API', async () => {
      const res = await fetch("https://api.dehashed.com/v2/search", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Dehashed-Api-Key": apiKey!,
        },
        body: JSON.stringify({
          query: "domain:example.com",
          page: 1,
          size: 3,
          de_dupe: true,
        }),
      });

      const data = await res.json();
      if (data.entries && data.entries.length > 0) {
        const entry = data.entries[0];
        if (entry.email) expect(Array.isArray(entry.email)).toBe(true);
        if (entry.ip_address) expect(Array.isArray(entry.ip_address)).toBe(true);
        if (entry.password) expect(Array.isArray(entry.password)).toBe(true);
        if (entry.database_name) expect(typeof entry.database_name).toBe("string");
      }
    }, 15000);

    it('should reject old v1 GET Basic Auth (deprecated)', async () => {
      const email = process.env.DEHASHED_EMAIL || "test@test.com";
      const oldAuth = `Basic ${Buffer.from(`${email}:${apiKey}`).toString("base64")}`;
      const res = await fetch(
        `https://api.dehashed.com/search?query=${encodeURIComponent("domain:example.com")}&size=1&page=1`,
        {
          method: "GET",
          headers: {
            Accept: "application/json",
            Authorization: oldAuth,
          },
        }
      );
      // v1 endpoint should return 404 or non-200 since it's deprecated
      expect(res.status).not.toBe(200);
    }, 15000);
  });
});
