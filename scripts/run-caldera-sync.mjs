import jwt from "jsonwebtoken";

const BASE_URL = "http://localhost:3000";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
const token = jwt.sign({ username: "admin", role: "admin", loginTime: Date.now() }, JWT_SECRET, { expiresIn: "2h" });
const COOKIE = `caldera_session=${token}`;

console.log("=== Caldera Adversary Sync ===");
console.log("Syncing 495 adversaries with 1,940 abilities...\n");

const start = Date.now();
try {
  const resp = await fetch(`${BASE_URL}/api/trpc/threatActorDb.syncCaldera`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: COOKIE },
    body: JSON.stringify({ json: {} }),
  });

  if (resp.status >= 400) {
    const text = await resp.text();
    console.error(`HTTP ${resp.status}: ${text.slice(0, 500)}`);
    process.exit(1);
  }

  const data = await resp.json();
  const r = data.result?.data?.json || data.result?.data || data;
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  console.log(`\nDone in ${elapsed}s`);
  console.log(`Total Caldera Adversaries: ${r.totalCalderaAdversaries}`);
  console.log(`Synced: ${r.created}`);
  console.log(`Skipped: ${r.skipped}`);
  console.log(`Abilities Mapped: ${r.abilitiesSynced}`);
  if (r.errors?.length) {
    console.log(`Errors: ${r.errors.length}`);
    r.errors.slice(0, 10).forEach(e => console.log(`  - ${e}`));
  }
} catch (e) {
  console.error(`Failed (${((Date.now() - start) / 1000).toFixed(1)}s):`, e.message);
}
