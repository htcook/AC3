#!/usr/bin/env node
/**
 * Reset password for harrison.cook@gmail.com via admin API
 */
import http from "http";

const BASE = "http://localhost:3000";

function request(path, body, cookie = "") {
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
  // Login as admin
  const loginRes = await request("/api/trpc/calderaAuth.login", {
    json: { username: "admin", password: "PVYedK$BUAYzyXaAegdEl2Dz" },
  });
  const sessionCookie = loginRes.cookies
    .find((c) => c.startsWith("caldera_session="))
    ?.split(";")[0];

  if (!sessionCookie) {
    console.error("Login failed");
    process.exit(1);
  }

  // Reset password for account ID 1 (harrison.cook@gmail.com)
  const resetRes = await request(
    "/api/trpc/accountAuth.resetPassword",
    { json: { accountId: 1 } },
    sessionCookie
  );

  const result = resetRes.body?.result?.data?.json;
  if (result?.success) {
    console.log("=== Password Reset Successful ===");
    console.log(`Email: harrison.cook@gmail.com`);
    console.log(`Temporary Password: ${result.tempPassword}`);
    console.log("(Must change on first login)");
  } else {
    console.error("Reset failed:", JSON.stringify(resetRes.body, null, 2));
  }
}

main().catch(console.error);
