import jwt from "jsonwebtoken";

const BASE_URL = "http://localhost:3000";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
const token = jwt.sign({ username: "admin", role: "admin", loginTime: Date.now() }, JWT_SECRET, { expiresIn: "2h" });
const COOKIE = `caldera_session=${token}`;

async function callTrpc(path, input = {}, timeout = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${BASE_URL}/api/trpc/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: COOKIE },
      body: JSON.stringify({ json: input }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (resp.status >= 400) {
      const t = await resp.text();
      throw new Error(`HTTP ${resp.status}: ${t.slice(0, 500)}`);
    }
    const data = await resp.json();
    return data.result?.data?.json || data.result?.data || data;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// OP 2: Caldera Sync
console.log("=== OPERATION 2: Caldera Adversary Sync ===");
const syncStart = Date.now();
try {
  const r = await callTrpc("threatActorDb.syncCaldera", {}, 120000);
  console.log(`Done in ${((Date.now() - syncStart) / 1000).toFixed(1)}s`);
  console.log(`Total Caldera Adversaries: ${r.totalCalderaAdversaries}`);
  console.log(`Created: ${r.created}, Updated: ${r.updated}, Skipped: ${r.skipped}`);
  if (r.errors?.length) console.log(`Errors: ${r.errors.length}`);
} catch (e) {
  console.error(`Sync failed (${((Date.now() - syncStart) / 1000).toFixed(1)}s):`, e.message);
}

// OP 3: Domain Intel Scan
console.log("\n=== OPERATION 3: Domain Intel Scan - AceofCloud.com ===");
const scanStart = Date.now();
try {
  const r = await callTrpc("domainIntel.startScan", {
    primaryDomain: "aceofcloud.com",
    clientType: "enterprise",
    sector: "Cloud & Cybersecurity Services",
    customerName: "AceofCloud",
    criticalFunctions: ["Cloud Infrastructure", "Cybersecurity Consulting", "Red Team Operations", "Managed Security"],
    complianceFlags: ["SOC2", "NIST"],
    notes: "Full end-to-end pipeline test with threat actor matching"
  }, 300000);
  console.log(`Done in ${((Date.now() - scanStart) / 1000).toFixed(1)}s`);
  console.log(`Scan ID: ${r.scanId}`);
  console.log(`Status: ${r.status}`);
  
  // Print pipeline output summary
  if (r.pipelineOutput) {
    const po = r.pipelineOutput;
    if (po.stage1) console.log(`Stage 1 (Discovery): ${po.stage1.subdomains?.length || 0} subdomains, ${po.stage1.dnsRecords?.length || 0} DNS records`);
    if (po.stage2) console.log(`Stage 2 (Passive Scan): ${po.stage2.technologies?.length || 0} technologies, ${po.stage2.openPorts?.length || 0} open ports`);
    if (po.stage3) console.log(`Stage 3 (Risk Analysis): Risk score ${po.stage3.overallRiskScore || "N/A"}`);
    if (po.stage4) console.log(`Stage 4 (Recommendations): ${po.stage4.campaigns?.length || 0} campaign recommendations`);
  }
  
  if (r.threatActorMatches) {
    const matches = Array.isArray(r.threatActorMatches) ? r.threatActorMatches : [];
    console.log(`\nThreat Actor Matches: ${matches.length}`);
    matches.slice(0, 15).forEach((m, i) => {
      console.log(`  ${i + 1}. ${m.name || m.actorName || "Unknown"} - Score: ${m.score || m.matchScore || "N/A"} - ${m.matchReasons?.join(", ") || ""}`);
    });
  }
  
  // Write full result to file for inspection
  const fs = await import("fs");
  fs.writeFileSync("/home/ubuntu/caldera-dashboard/scan-result.json", JSON.stringify(r, null, 2));
  console.log("\nFull result saved to scan-result.json");
} catch (e) {
  console.error(`Scan failed (${((Date.now() - scanStart) / 1000).toFixed(1)}s):`, e.message);
}
