import jwt from "jsonwebtoken";
const BASE = "http://localhost:3000/api/trpc";
const JWT_SECRET = "caldera-dashboard-secret-key-2024";
const token = jwt.sign({ username: "admin", role: "admin", loginTime: Date.now() }, JWT_SECRET, { expiresIn: "1h" });
const headers = { "Content-Type": "application/json", Cookie: `caldera_session=${token}` };

async function query(procedure, input) {
  const url = input ? `${BASE}/${procedure}?input=${encodeURIComponent(JSON.stringify({ json: input }))}` : `${BASE}/${procedure}`;
  const res = await fetch(url, { headers });
  return (await res.json()).result?.data?.json;
}

const state = await query("engagementOps.getState", { engagementId: 1350014 });
console.log("Full log:");
for (const log of (state?.log || [])) {
  console.log(`[${log.type}] ${log.title}: ${log.detail}`);
}
