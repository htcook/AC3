import { describe, it, expect } from "vitest";

describe("ZAP Connection Validation", () => {
  it("should connect to ZAP API and get version", async () => {
    const ZAP_BASE_URL = process.env.ZAP_BASE_URL;
    const ZAP_API_KEY = process.env.ZAP_API_KEY;
    
    console.log('ZAP_BASE_URL:', ZAP_BASE_URL);
    console.log('ZAP_API_KEY present:', !!ZAP_API_KEY);
    
    expect(ZAP_BASE_URL).toBeDefined();
    expect(ZAP_API_KEY).toBeDefined();
    
    const url = `${ZAP_BASE_URL}/JSON/core/view/version/?apikey=${ZAP_API_KEY}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    expect(res.ok).toBe(true);
    
    const data = await res.json();
    expect(data.version).toBeDefined();
    expect(data.version).toMatch(/^\d+\.\d+\.\d+$/);
    console.log("ZAP version:", data.version);
  });
});
