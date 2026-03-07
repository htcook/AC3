import jwt from "jsonwebtoken";
const token = jwt.sign({username:"admin",role:"admin",loginTime:Date.now()},"caldera-dashboard-secret-key-2024",{expiresIn:"2h"});
const headers = {Cookie:"caldera_session="+token};
const BASE = "http://localhost:3000/api/trpc";

async function query(proc, input) {
  const url = input ? `${BASE}/${proc}?input=${encodeURIComponent(JSON.stringify({json:input}))}` : `${BASE}/${proc}`;
  const res = await fetch(url, {headers});
  const data = await res.json();
  return data.result?.data?.json ?? data.result?.data;
}

const state = await query("engagementOps.getState", {engagementId:1350014});
const a = (state?.assets||[]).find(x => x.hostname === "testphp.vulnweb.com");
if (!a) { console.log("Asset not found"); process.exit(1); }

const signals = a.passiveRecon?.riskSignals || [];
console.log("Total signals:", signals.length);

// Search for file inclusion, crlf, directory traversal keywords
const keywords = ["file inclusion", "lfi", "rfi", "local file", "crlf", "header injection", "response splitting", "directory traversal", "path traversal", "directory listing", "dir traversal"];
for (const kw of keywords) {
  const matches = signals.filter(s => ((s.rationale||"")+" "+(s.title||"")).toLowerCase().includes(kw));
  if (matches.length > 0) {
    console.log(`\nFound "${kw}" in ${matches.length} signals:`);
    for (const m of matches.slice(0, 3)) {
      console.log("  [" + (m.severity||"?") + "] " + (m.rationale||m.title||"").slice(0, 150));
    }
  }
}

// Also check vuln descriptions more carefully
console.log("\n\nVuln titles and descriptions:");
for (const v of (a.vulns||[])) {
  console.log("[" + v.severity + "] " + v.title);
  console.log("  desc: " + (v.description||"").slice(0, 200));
  console.log("  cat: " + (v.category||""));
}
