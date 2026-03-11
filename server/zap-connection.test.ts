import { describe, it, expect } from "vitest";
import { HttpProxyAgent } from "http-proxy-agent";
import http from "http";

/**
 * Helper to make an HTTP request through ZAP proxy.
 * ZAP API is accessed via "http://zap/..." through the proxy at ZAP_BASE_URL.
 */
function zapGet(url: string, proxyUrl: string): Promise<{ status: number; body: any }> {
  const agent = new HttpProxyAgent(proxyUrl);
  return new Promise((resolve, reject) => {
    const req = http.get(url, { agent, timeout: 15000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode || 0, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode || 0, body: data });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

describe("ZAP Connection Validation", () => {
  it("should connect to ZAP API and get version via proxy", async () => {
    const ZAP_BASE_URL = process.env.ZAP_BASE_URL;
    const ZAP_API_KEY = process.env.ZAP_API_KEY;
    
    console.log('ZAP_BASE_URL:', ZAP_BASE_URL);
    console.log('ZAP_API_KEY present:', !!ZAP_API_KEY);
    
    expect(ZAP_BASE_URL).toBeDefined();
    expect(ZAP_API_KEY).toBeDefined();
    
    const apiUrl = `http://zap/JSON/core/view/version/?apikey=${ZAP_API_KEY}`;
    const result = await zapGet(apiUrl, ZAP_BASE_URL!);
    
    expect(result.status).toBe(200);
    expect(result.body.version).toBeDefined();
    expect(result.body.version).toMatch(/^\d+\.\d+\.\d+$/);
    console.log("ZAP version:", result.body.version);
  });

  it("should be able to list scan policies", async () => {
    const ZAP_BASE_URL = process.env.ZAP_BASE_URL;
    const ZAP_API_KEY = process.env.ZAP_API_KEY;
    
    const apiUrl = `http://zap/JSON/ascan/view/scanPolicyNames/?apikey=${ZAP_API_KEY}`;
    const result = await zapGet(apiUrl, ZAP_BASE_URL!);
    
    expect(result.status).toBe(200);
    console.log("ZAP scan policies:", JSON.stringify(result.body));
    expect(result.body).toBeDefined();
  });
});
