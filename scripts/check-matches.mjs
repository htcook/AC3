import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000";
const CALDERA_JWT_SECRET = 'caldera-dashboard-secret-key-2024';
const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: "1h" }
);
const cookie = `caldera_session=${token}`;

async function run() {
  // Get the scan data via tRPC
  const res = await fetch(`${BASE}/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ json: { id: 30122 } }))}`, {
    headers: { Cookie: cookie },
  });
  const data = await res.json();
  const scan = data.result?.data?.json;
  
  if (!scan) {
    console.log("No scan found, raw:", JSON.stringify(data).slice(0, 500));
    return;
  }
  
  const pipeline = scan.pipelineOutput || scan.pipeline_output;
  const matches = pipeline?.threatActorMatches?.matches || [];
  
  console.log("Total matches:", matches.length);
  if (matches.length > 0) {
    const first = matches[0];
    console.log("\nFirst actor keys:", Object.keys(first));
    console.log("Name:", first.name || first.actorId);
    console.log("techniques type:", typeof first.techniques, Array.isArray(first.techniques));
    console.log("relevantTechniques type:", typeof first.relevantTechniques, Array.isArray(first.relevantTechniques));
    
    if (first.techniques && first.techniques.length > 0) {
      console.log("\nFirst technique:", JSON.stringify(first.techniques[0]));
      console.log("Type of first technique:", typeof first.techniques[0]);
    }
    if (first.relevantTechniques && first.relevantTechniques.length > 0) {
      console.log("\nFirst relevantTechnique:", JSON.stringify(first.relevantTechniques[0]));
      console.log("Type of first relevantTechnique:", typeof first.relevantTechniques[0]);
    }
  }
  
  // Also check campaign recommendations
  const campaigns = pipeline?.campaignRecommendations || [];
  console.log("\nCampaign recommendations:", campaigns.length);
  if (campaigns.length > 0) {
    const first = campaigns[0];
    console.log("First campaign keys:", Object.keys(first));
    if (first.attackChain && first.attackChain.length > 0) {
      console.log("First attack chain step:", JSON.stringify(first.attackChain[0]));
    }
  }
}

run();
