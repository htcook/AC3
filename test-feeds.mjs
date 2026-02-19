import { createTRPCClient, httpBatchLink } from "@trpc/client";
import superjson from "superjson";

// Test the actual server endpoints directly
const BASE = "http://localhost:3000";

async function testEndpoint(name, path) {
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
    });
    const text = await res.text();
    if (!res.ok) {
      console.log(`❌ ${name}: HTTP ${res.status}`);
      console.log(`   Response: ${text.substring(0, 500)}`);
    } else {
      const data = JSON.parse(text);
      console.log(`✅ ${name}: OK`);
      if (data.result?.data) {
        const inner = data.result.data;
        console.log(`   Data keys: ${Object.keys(inner).join(", ")}`);
      }
    }
  } catch (err) {
    console.log(`❌ ${name}: ${err.message}`);
  }
}

async function testTrpcBatch(name, procedures) {
  try {
    const params = procedures.map((p, i) => `${i}=${encodeURIComponent(JSON.stringify(p))}`).join("&");
    const url = `${BASE}/api/trpc/${procedures.map(p => p.path).join(",")}?batch=1&input=${encodeURIComponent(JSON.stringify(procedures.reduce((acc, p, i) => { acc[i] = p.input || { json: null }; return acc; }, {})))}`;
    
    console.log(`\nTesting: ${name}`);
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json" },
    });
    const text = await res.text();
    if (!res.ok) {
      console.log(`❌ HTTP ${res.status}: ${text.substring(0, 500)}`);
    } else {
      try {
        const data = JSON.parse(text);
        for (let i = 0; i < data.length; i++) {
          const item = data[i];
          if (item.error) {
            console.log(`❌ ${procedures[i].path}: ${JSON.stringify(item.error).substring(0, 300)}`);
          } else {
            console.log(`✅ ${procedures[i].path}: OK`);
          }
        }
      } catch (e) {
        console.log(`Parse error: ${e.message}`);
        console.log(`Raw: ${text.substring(0, 500)}`);
      }
    }
  } catch (err) {
    console.log(`❌ ${name}: ${err.message}`);
  }
}

// Test individual endpoints
console.log("=== Testing Vuln Intel (KevDashboard) endpoints ===");

// Test calderaProxy.getVulnFeedStats
await testTrpcBatch("Vuln Feed Stats", [
  { path: "calderaProxy.getVulnFeedStats", input: { json: null } }
]);

// Test calderaProxy.getRecentZeroDays
await testTrpcBatch("Recent Zero Days", [
  { path: "calderaProxy.getRecentZeroDays", input: { json: { limit: 10 } } }
]);

// Test calderaProxy.getWeaponizedCves
await testTrpcBatch("Weaponized CVEs", [
  { path: "calderaProxy.getWeaponizedCves", input: { json: { limit: 10 } } }
]);

// Test calderaProxy.getKevCatalog
await testTrpcBatch("KEV Catalog", [
  { path: "calderaProxy.getKevCatalog", input: { json: null } }
]);

console.log("\n=== Testing IOC Feed endpoints ===");

// Test iocFeed.list
await testTrpcBatch("IOC Feed List", [
  { path: "iocFeed.list", input: { json: { limit: 10 } } }
]);

// Test iocFeed.stats
await testTrpcBatch("IOC Feed Stats", [
  { path: "iocFeed.stats", input: { json: null } }
]);

console.log("\nDone.");
