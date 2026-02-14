import jwt from "jsonwebtoken";

const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  "caldera-dashboard-secret-key-2024",
  { expiresIn: "1h" }
);

const res = await fetch(
  "http://localhost:3000/api/trpc/domainIntel.getScan?input=" +
    encodeURIComponent(JSON.stringify({ json: { id: 30122 } })),
  { headers: { Cookie: "caldera_session=" + token } }
);

const data = await res.json();
const scanObj = data.result?.data?.json;

console.log("Top-level keys:", Object.keys(scanObj || {}));

const scan = scanObj?.scan || scanObj;
console.log("Scan keys:", Object.keys(scan || {}));

const po = scan?.pipelineOutput || scan?.pipeline_output;
if (po) {
  console.log("pipelineOutput keys:", Object.keys(po));
  
  const tam = po.threatActorMatches;
  if (tam) {
    const matches = tam.matches || (Array.isArray(tam) ? tam : []);
    console.log("Threat actor matches:", matches.length);
    if (matches.length > 0) {
      const first = matches[0];
      console.log("First match keys:", Object.keys(first));
      if (first.techniques) {
        console.log("techniques[0]:", JSON.stringify(first.techniques[0]));
        console.log("techniques type:", typeof first.techniques[0]);
      }
      if (first.relevantTechniques) {
        console.log("relevantTechniques[0]:", JSON.stringify(first.relevantTechniques[0]));
      }
    }
  } else {
    console.log("No threatActorMatches in pipelineOutput");
  }
  
  const cr = po.campaignRecommendations;
  if (cr) {
    console.log("Campaign recommendations:", cr.length);
    if (cr.length > 0) {
      console.log("First campaign keys:", Object.keys(cr[0]));
      if (cr[0].attackChain) {
        console.log("attackChain[0]:", JSON.stringify(cr[0].attackChain[0]));
      }
    }
  }
} else {
  console.log("No pipelineOutput found");
  console.log("Scan data sample:", JSON.stringify(scan).slice(0, 500));
}
