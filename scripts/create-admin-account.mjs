#!/usr/bin/env node
/**
 * Create admin account for harrison.cook@gmail.com
 * Uses the accountAuth.inviteUser endpoint via direct tRPC call
 */
import http from "http";
import crypto from "crypto";

const BASE = "http://localhost:3000";

// First we need to login as admin to get a session cookie
async function request(path, body, cookie = "") {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(path, BASE);
    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
        ...(cookie ? { Cookie: cookie } : {}),
      },
    };
    const req = http.request(opts, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        const cookies = res.headers["set-cookie"] || [];
        resolve({ status: res.statusCode, body: JSON.parse(body), cookies });
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function main() {
  console.log("=== Creating Admin Account: harrison.cook@gmail.com ===\n");

  // Step 1: Login as admin to get session cookie
  console.log("[1] Logging in as admin...");
  const loginRes = await request("/api/trpc/calderaAuth.login", {
    json: { username: "admin", password: "PVYedK$BUAYzyXaAegdEl2Dz" },
  });

  if (!loginRes.body?.result?.data?.json?.success) {
    console.error("Login failed:", loginRes.body);
    // Try with default password
    const loginRes2 = await request("/api/trpc/calderaAuth.login", {
      json: { username: "admin", password: "PVYedK$BUAYzyXaAegdEl2Dz" },
    });
    if (!loginRes2.body?.result?.data?.json?.success) {
      console.error("Login failed with default password too:", loginRes2.body);
      process.exit(1);
    }
    Object.assign(loginRes, loginRes2);
  }

  const sessionCookie = loginRes.cookies
    .find((c) => c.startsWith("caldera_session="))
    ?.split(";")[0];

  if (!sessionCookie) {
    console.error("No session cookie received");
    process.exit(1);
  }
  console.log("   ✓ Admin session established\n");

  // Step 2: Generate a secure temporary password
  const tempPassword = "Ace!" + crypto.randomBytes(8).toString("base64url") + "1a";
  console.log("[2] Generated temporary password");

  // Step 3: Invite harrison.cook@gmail.com as admin
  console.log("[3] Creating admin account for harrison.cook@gmail.com...");
  const inviteRes = await request(
    "/api/trpc/accountAuth.inviteUser",
    {
      json: {
        email: "harrison.cook@gmail.com",
        displayName: "Harrison Cook",
        role: "admin",
        tempPassword: tempPassword,
      },
    },
    sessionCookie
  );

  if (inviteRes.body?.result?.data?.json?.email) {
    const result = inviteRes.body.result.data.json;
    console.log("   ✓ Account created successfully!");
    console.log(`   Email: ${result.email}`);
    console.log(`   Role: ${result.role}`);
    console.log(`   Status: ${result.status}`);
    console.log(`\n   ─── Login Credentials ───`);
    console.log(`   Email: harrison.cook@gmail.com`);
    console.log(`   Temporary Password: ${tempPassword}`);
    console.log(`   ─── Must change on first login ───\n`);
  } else {
    console.error("Invite failed:", JSON.stringify(inviteRes.body, null, 2));
    // Check if it's a conflict (already exists)
    if (inviteRes.body?.error?.json?.message?.includes("already exists")) {
      console.log("\n   Account already exists. No action needed.");
    }
  }
}

main().catch(console.error);
