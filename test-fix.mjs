import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000/api/trpc";
const JWT_SECRET = "caldera-dashboard-secret-key-2024";
const ENGAGEMENT_ID = 1350014;

const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  JWT_SECRET,
  { expiresIn: "1h" }
);

const headers = {
  "Content-Type": "application/json",
  Cookie: `caldera_session=${token}`,
};

async function mutate(procedure, input) {
  const res = await fetch(`${BASE}/${procedure}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ json: input }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`${procedure}: ${data.error.json?.message || JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

async function query(procedure, input) {
  const url = input
    ? `${BASE}/${procedure}?input=${encodeURIComponent(JSON.stringify({ json: input }))}`
    : `${BASE}/${procedure}`;
  const res = await fetch(url, { headers });
  const data = await res.json();
  if (data.error) throw new Error(`${procedure}: ${data.error.json?.message || JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

async function main() {
  console.log("=== Testing Passive Recon Data Mapping Fix ===\n");

  // 1. Reset and trigger full pipeline
  console.log("1. Triggering full pipeline re-run with resetState...");
  try {
    const result = await mutate("engagementOps.rerunFullPipeline", {
      engagementId: ENGAGEMENT_ID,
      phases: { passive: true, active: false, llmAnalysis: false, exploitGeneration: false },
      resetState: true,
    });
    console.log(`   ✓ ${JSON.stringify(result)}`);
  } catch (e) {
    console.log(`   ✗ ${e.message}`);
  }

  // 2. Poll state every 15s for up to 5 minutes
  for (let i = 0; i < 20; i++) {
    console.log(`\n--- Poll ${i + 1} (${(i + 1) * 15}s) ---`);
    await new Promise(r => setTimeout(r, 15000));
    
    try {
      const state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
      console.log(`Phase: ${state?.phase}, Running: ${state?.isRunning}`);
      console.log(`Assets: ${state?.assets?.length || 0}`);
      
      let totalPorts = 0, totalVulns = 0, totalTechs = 0;
      for (const asset of (state?.assets || [])) {
        const ports = asset.ports?.length || 0;
        const vulns = asset.vulns?.length || 0;
        const techs = asset.passiveRecon?.technologies?.length || 0;
        const services = asset.passiveRecon?.services?.length || 0;
        const signals = asset.passiveRecon?.riskSignals?.length || 0;
        totalPorts += ports;
        totalVulns += vulns;
        totalTechs += techs;
        console.log(`  ${asset.hostname}: ${ports} ports, ${vulns} vulns, ${techs} techs, ${services} services, ${signals} signals, status=${asset.status}`);
      }
      console.log(`TOTALS: ${totalPorts} ports, ${totalVulns} vulns, ${totalTechs} techs`);
      
      // Check recent logs
      const recentLogs = (state?.log || []).slice(-5);
      for (const log of recentLogs) {
        console.log(`  LOG: [${log.type}] ${log.title}`);
      }
      
      if (!state?.isRunning) {
        console.log("\n✅ Pipeline finished!");
        break;
      }
    } catch (e) {
      console.log(`   ✗ ${e.message}`);
    }
  }
}

main().catch(console.error);
