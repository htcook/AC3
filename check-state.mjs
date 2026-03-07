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
console.log("Phase:", state?.phase, "Running:", state?.isRunning);
const totalVulns = (state?.assets||[]).reduce((s,a)=>s+(a.vulns?.length||0),0);
console.log("Total Vulns:", totalVulns, "Assets:", state?.assets?.length);

for (const target of ["testphp.vulnweb.com","demo.testfire.net","demo.owasp-juice.shop"]) {
  const a = (state?.assets||[]).find(x => x.hostname === target);
  if (!a) continue;
  console.log("\n" + target + ": " + (a.vulns?.length||0) + " vulns");
  for (const v of (a.vulns||[])) {
    console.log("  [" + v.severity + "] " + v.title + " [" + (v.category||"") + "] conf=" + v.confidence);
  }
}

// Accuracy
const targets = {
  "testphp.vulnweb.com": {"SQL Injection":["sql injection","sqli","sql"],"XSS":["xss","cross-site scripting"],"File Inclusion":["file inclusion","lfi","rfi","local file"],"CRLF Injection":["crlf","header injection","response splitting"],"Directory Traversal":["directory traversal","path traversal","directory listing"]},
  "demo.testfire.net": {"SQL Injection":["sql injection","sqli","sql"],"XSS":["xss","cross-site scripting"],"Authentication Bypass":["authentication","auth bypass","broken auth","login","credential","session"],"Information Disclosure":["information disclosure","info disclosure","data exposure","sensitive data"]},
  "demo.owasp-juice.shop": {"SQL Injection":["sql injection","sqli","sql","nosql"],"XSS":["xss","cross-site scripting"],"Broken Authentication":["authentication","auth","broken auth","login","credential","session","password"],"Sensitive Data Exposure":["sensitive data","data exposure","data leak","information disclosure","pii","credential"]},
};
let total = 0, found = 0;
for (const [target, kws] of Object.entries(targets)) {
  const a = (state?.assets||[]).find(x => x.hostname === target);
  if (!a) continue;
  const allText = [...(a.vulns||[]).map(v=>(v.title+" "+(v.description||"")+" "+(v.category||"")).toLowerCase()),...(a.passiveRecon?.riskSignals||[]).map(s=>(s.rationale||"").toLowerCase())].join(" | ");
  console.log("\n" + target + ":");
  for (const [name, kwList] of Object.entries(kws)) {
    const ok = kwList.some(kw => allText.includes(kw));
    console.log("  " + (ok?"✅":"❌") + " " + name);
    total++; if (ok) found++;
  }
}
console.log("\nOVERALL: " + found + "/" + total + " (" + Math.round(found/total*100) + "%)");

// Exploits
try {
  const exploits = await query("engagementOps.getGeneratedExploits", {engagementId:1350014});
  const arr = Array.isArray(exploits) ? exploits : [];
  console.log("\nExploits: " + arr.length);
  for (const e of arr.slice(0,20)) {
    console.log("  " + e.filename + " [" + e.language + "] -> " + e.asset + " (" + e.confidence + "%)");
  }
} catch(e) { console.log("Exploits error:", e.message); }

console.log("\nLast 10 logs:");
for (const l of (state?.log||[]).slice(-10)) {
  console.log("  ["+l.type+"] "+l.title+": "+(l.detail||"").slice(0,100));
}
