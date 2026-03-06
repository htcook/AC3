import { describe, it, expect } from 'vitest';

describe('AbuseIPDB API Key Validation', () => {
  it('should authenticate with AbuseIPDB API', async () => {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    expect(apiKey).toBeTruthy();
    expect(apiKey!.length).toBeGreaterThan(20);

    // Check a well-known malicious IP (8.8.8.8 is Google DNS, low abuse score)
    const res = await fetch(
      'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90',
      {
        headers: {
          Key: apiKey!,
          Accept: 'application/json',
        },
      }
    );

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.data).toBeTruthy();
    expect(data.data.ipAddress).toBe('8.8.8.8');
    console.log(`AbuseIPDB key valid — checked 8.8.8.8, abuse score: ${data.data.abuseConfidenceScore}%`);
  });
});
