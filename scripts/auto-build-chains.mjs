import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000";
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

const CALDERA_JWT_SECRET = 'caldera-dashboard-secret-key-2024';
const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: "1h" }
);

const cookie = `caldera_session=${token}`;
const SCAN_ID = 30122; // AceofCloud scan

async function run() {
  console.log("=== Auto-Building Chains for All Paused Operations ===\n");

  try {
    const res = await fetch(`${BASE}/api/trpc/calderaProxy.autoBuildAllChains`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ json: { scanId: 30122 } }),
    });

    const data = await res.json();

    if (data.result?.data?.json) {
      const result = data.result.data.json;
      console.log(`Total operations processed: ${result.totalOperations}\n`);
      for (const op of result.results) {
        console.log(`  ✓ ${op.operationName}`);
        console.log(`    Adversary: ${op.adversaryName}`);
        console.log(`    Abilities: ${op.totalAbilities}`);
        console.log(`    Techniques Covered: ${op.techniquesCovered}`);
        console.log(`    Techniques Not Covered: ${op.techniquesNotCovered}\n`);
      }
    } else {
      console.log("Response:", JSON.stringify(data, null, 2));
    }
  } catch (err) {
    console.error("Error:", err.message);
  }
}

run();
