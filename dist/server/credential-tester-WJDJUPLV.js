import {
  getBuiltinCreds,
  init_oem_default_creds,
  matchCredentialsForTechnology
} from "./chunk-YBXDAJGB.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-GM677ZS3.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/credential-tester.ts
import * as net from "net";
async function testSshCredential(host, port, username, password, timeoutMs = 8e3) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: "timeout" });
    }, timeoutMs);
    const socket = net.createConnection({ host, port }, () => {
      let data = "";
      socket.on("data", (chunk) => {
        data += chunk.toString("utf-8");
        if (data.includes("SSH-") && !data.includes("CalderaCredTest")) {
          socket.write("SSH-2.0-CalderaCredTest_1.0\r\n");
        }
      });
      socket.on("error", (err) => {
        clearTimeout(timer);
        resolve({ status: "error", error: err.message });
      });
      setTimeout(() => {
        clearTimeout(timer);
        socket.destroy();
        resolve({
          status: "skipped",
          response: data.slice(0, 500),
          error: "SSH auth requires ssh2 client \u2014 credential stored for manual/automated testing"
        });
      }, 3e3);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: "error", error: err.message });
    });
  });
}
async function testFtpCredential(host, port, username, password, timeoutMs = 8e3) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: "timeout" });
    }, timeoutMs);
    let phase = "banner";
    let responseData = "";
    const socket = net.createConnection({ host, port }, () => {
      socket.on("data", (chunk) => {
        const text = chunk.toString("utf-8");
        responseData += text;
        if (phase === "banner" && /^220/m.test(text)) {
          phase = "user";
          socket.write(`USER ${username}\r
`);
        } else if (phase === "user") {
          if (/^331/m.test(text)) {
            phase = "pass";
            socket.write(`PASS ${password}\r
`);
          } else if (/^230/m.test(text)) {
            phase = "done";
            socket.write("QUIT\r\n");
            clearTimeout(timer);
            resolve({ status: "success", response: responseData.slice(0, 500) });
          } else if (/^530|^421|^500/m.test(text)) {
            phase = "done";
            socket.destroy();
            clearTimeout(timer);
            resolve({ status: "failed", response: responseData.slice(0, 500) });
          }
        } else if (phase === "pass") {
          if (/^230/m.test(text)) {
            phase = "done";
            socket.write("QUIT\r\n");
            clearTimeout(timer);
            resolve({ status: "success", response: responseData.slice(0, 500) });
          } else {
            phase = "done";
            socket.destroy();
            clearTimeout(timer);
            resolve({ status: "failed", response: responseData.slice(0, 500) });
          }
        }
      });
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: "error", error: err.message });
    });
  });
}
async function testHttpCredential(host, port, username, password, timeoutMs = 1e4) {
  const protocol = port === 443 || port === 8443 ? "https" : "http";
  const portSuffix = port === 80 || port === 443 ? "" : `:${port}`;
  const baseUrl = `${protocol}://${host}${portSuffix}`;
  const adminPaths = ["/", "/login", "/admin", "/admin/login", "/manager/html", "/wp-login.php"];
  try {
    const basicAuth = Buffer.from(`${username}:${password}`).toString("base64");
    for (const path of adminPaths) {
      try {
        const resp = await fetch(`${baseUrl}${path}`, {
          method: "GET",
          headers: {
            "Authorization": `Basic ${basicAuth}`,
            "User-Agent": "Mozilla/5.0 (compatible; CalderaCredTest/1.0)"
          },
          signal: AbortSignal.timeout(timeoutMs),
          redirect: "follow"
        });
        if (resp.status === 200 && resp.headers.get("www-authenticate") === null) {
          const body = await resp.text().catch(() => "");
          if (/dashboard|admin|manage|control|panel|settings|configuration|logout|sign.?out/i.test(body)) {
            return {
              status: "success",
              response: `HTTP Basic Auth succeeded on ${path} (${resp.status}). Body contains admin keywords.`
            };
          }
        }
        if (resp.status === 401) {
          continue;
        }
      } catch {
        continue;
      }
    }
    for (const loginPath of ["/login", "/admin/login", "/wp-login.php", "/user/login"]) {
      try {
        const formData = new URLSearchParams();
        formData.append("username", username);
        formData.append("password", password);
        formData.append("user", username);
        formData.append("pass", password);
        formData.append("log", username);
        formData.append("pwd", password);
        const resp = await fetch(`${baseUrl}${loginPath}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (compatible; CalderaCredTest/1.0)"
          },
          body: formData.toString(),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: "manual"
          // Don't follow redirects — a redirect often means success
        });
        if (resp.status === 302 || resp.status === 303) {
          const location = resp.headers.get("location") || "";
          if (/dashboard|admin|home|index|panel|welcome/i.test(location)) {
            return {
              status: "success",
              response: `Form login succeeded on ${loginPath} \u2192 redirect to ${location}`
            };
          }
        }
      } catch {
        continue;
      }
    }
    return { status: "failed", response: "No admin panel responded to default credentials" };
  } catch (err) {
    return { status: "error", error: err.message };
  }
}
async function testTelnetCredential(host, port, username, password, timeoutMs = 1e4) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: "timeout" });
    }, timeoutMs);
    let phase = "wait_login";
    let responseData = "";
    const socket = net.createConnection({ host, port }, () => {
      socket.on("data", (chunk) => {
        const text = chunk.toString("utf-8");
        responseData += text;
        if (phase === "wait_login" && /login:|username:/i.test(responseData)) {
          phase = "wait_pass";
          socket.write(`${username}\r
`);
        } else if (phase === "wait_pass" && /password:/i.test(text)) {
          phase = "wait_result";
          socket.write(`${password}\r
`);
        } else if (phase === "wait_result") {
          if (/\$|#|>|welcome|last login|logged in/i.test(text)) {
            phase = "done";
            socket.write("exit\r\n");
            clearTimeout(timer);
            resolve({ status: "success", response: responseData.slice(0, 500) });
          } else if (/login incorrect|authentication failure|access denied|invalid/i.test(text)) {
            phase = "done";
            socket.destroy();
            clearTimeout(timer);
            resolve({ status: "failed", response: responseData.slice(0, 500) });
          }
        }
      });
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: "error", error: err.message });
    });
  });
}
async function testRedisCredential(host, port, username, password, timeoutMs = 5e3) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: "timeout" });
    }, timeoutMs);
    const socket = net.createConnection({ host, port }, () => {
      const authCmd = password ? `AUTH ${password}\r
` : "PING\r\n";
      socket.write(authCmd);
      socket.on("data", (chunk) => {
        const text = chunk.toString("utf-8").trim();
        clearTimeout(timer);
        if (text.startsWith("+OK") || text.startsWith("+PONG")) {
          socket.write("QUIT\r\n");
          resolve({ status: "success", response: text });
        } else if (text.startsWith("-NOAUTH") || text.startsWith("-ERR")) {
          socket.destroy();
          resolve({ status: "failed", response: text });
        } else {
          socket.destroy();
          resolve({ status: "failed", response: text });
        }
      });
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: "error", error: err.message });
    });
  });
}
async function testMysqlCredential(host, port, username, password, timeoutMs = 8e3) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: "timeout" });
    }, timeoutMs);
    const socket = net.createConnection({ host, port }, () => {
      socket.on("data", (chunk) => {
        clearTimeout(timer);
        const text = chunk.toString("utf-8");
        socket.destroy();
        resolve({
          status: "skipped",
          response: text.slice(0, 200),
          error: "MySQL auth requires mysql2 driver \u2014 credential stored for automated testing"
        });
      });
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: "error", error: err.message });
    });
  });
}
async function getCredentialsForService(target) {
  const candidates = [];
  const seen = /* @__PURE__ */ new Set();
  if (target.technologies) {
    for (const tech of target.technologies) {
      const matches = await matchCredentialsForTechnology({
        ...tech,
        port: target.port,
        protocol: target.protocol,
        banner: target.banner
      });
      for (const m of matches) {
        const key = `${m.username}:${m.password}:${m.protocol}`;
        if (!seen.has(key)) {
          seen.add(key);
          candidates.push({ ...m, source: m.source || "OEM database" });
        }
      }
    }
  }
  if (target.product) {
    const matches = await matchCredentialsForTechnology({
      name: target.product,
      port: target.port,
      protocol: target.protocol,
      banner: target.banner
    });
    for (const m of matches) {
      const key = `${m.username}:${m.password}:${m.protocol}`;
      if (!seen.has(key)) {
        seen.add(key);
        candidates.push({ ...m, source: m.source || "OEM database" });
      }
    }
  }
  if (target.banner) {
    const bannerLower = target.banner.toLowerCase();
    const creds = getBuiltinCreds();
    for (const cred of creds) {
      if (bannerLower.includes(cred.vendor.toLowerCase()) || bannerLower.includes(cred.product.toLowerCase())) {
        const key = `${cred.username}:${cred.password}:${cred.protocol}`;
        if (!seen.has(key)) {
          seen.add(key);
          candidates.push({ ...cred, source: cred.source || "Banner match" });
        }
      }
    }
  }
  if (candidates.length === 0) {
    const genericMatches = await matchCredentialsForTechnology({
      name: "generic",
      port: target.port,
      protocol: target.protocol
    });
    for (const m of genericMatches) {
      if (m.vendor === "Generic") {
        const key = `${m.username}:${m.password}:${m.protocol}`;
        if (!seen.has(key)) {
          seen.add(key);
          candidates.push({ ...m, source: "Generic fallback" });
        }
      }
    }
  }
  return candidates;
}
async function testCredential(target, credential, timeoutMs = 8e3) {
  const start = Date.now();
  const protocol = credential.protocol.toLowerCase();
  const tester = PROTOCOL_TESTERS[protocol];
  if (!tester) {
    return {
      target,
      credential,
      status: "skipped",
      durationMs: Date.now() - start,
      error: `No tester available for protocol: ${protocol}. Credential stored for manual testing.`,
      timestamp: Date.now()
    };
  }
  const result = await tester(target.host, target.port, credential.username, credential.password, timeoutMs);
  return {
    target,
    credential,
    status: result.status,
    confirmedAccess: result.status === "success" ? credential.accessLevel : void 0,
    responseSnippet: result.response,
    durationMs: Date.now() - start,
    error: result.error,
    timestamp: Date.now()
  };
}
async function runCredentialTests(targets, options) {
  const concurrency = options?.concurrency || 3;
  const timeoutMs = options?.timeoutMs || 8e3;
  const maxCredsPerTarget = options?.maxCredsPerTarget || 10;
  const protocolFilter = options?.protocolFilter;
  const allResults = [];
  const byTarget = /* @__PURE__ */ new Map();
  if (options?.engagementId) {
    try {
      const { filterInScopeTargets } = await import("./scope-guard-JZ327Z7X.js");
      const scopeResult = await filterInScopeTargets({
        engagementId: options.engagementId,
        targets: targets.map((t) => ({ value: t.host })),
        tool: "Credential Tester",
        operatorId: options.operatorId || "system"
      });
      const inScopeHosts = new Set(scopeResult.inScope.map((t) => t.value));
      targets = targets.filter((t) => inScopeHosts.has(t.host));
    } catch {
      console.warn("[CredentialTester] Scope check failed, proceeding with all targets");
    }
  }
  const testQueue = [];
  for (const target of targets) {
    const candidates = getCredentialsForService(target);
    const filtered = protocolFilter ? candidates.filter((c) => protocolFilter.includes(c.protocol.toLowerCase())) : candidates;
    const limited = filtered.slice(0, maxCredsPerTarget);
    for (const cred of limited) {
      testQueue.push({ target, credential: cred });
    }
  }
  console.log(`[CredentialTester] Testing ${testQueue.length} credentials across ${targets.length} targets`);
  const queue = [...testQueue];
  const running = [];
  while (queue.length > 0 || running.length > 0) {
    while (running.length < concurrency && queue.length > 0) {
      const item = queue.shift();
      const promise = testCredential(item.target, item.credential, timeoutMs).then((result) => {
        allResults.push(result);
        const targetKey = `${item.target.host}:${item.target.port}`;
        if (!byTarget.has(targetKey)) byTarget.set(targetKey, []);
        byTarget.get(targetKey).push(result);
        if (result.status === "success") {
          console.log(
            `[CredentialTester] \u2713 ${item.credential.vendor} ${item.credential.product} ${item.credential.username}:*** @ ${item.target.host}:${item.target.port} (${item.credential.protocol})`
          );
        }
      }).then(() => {
        running.splice(running.indexOf(promise), 1);
      });
      running.push(promise);
    }
    if (running.length > 0) {
      await Promise.race(running);
    }
  }
  return {
    totalTargets: targets.length,
    totalCredentialsTested: allResults.length,
    successfulLogins: allResults.filter((r) => r.status === "success").length,
    failedAttempts: allResults.filter((r) => r.status === "failed").length,
    timeouts: allResults.filter((r) => r.status === "timeout").length,
    errors: allResults.filter((r) => r.status === "error").length,
    results: allResults,
    byTarget
  };
}
async function enrichFingerprintsWithCredentialTests(fingerprintResults, technologies, options) {
  const targets = fingerprintResults.map((fp) => ({
    host: fp.host,
    port: fp.port,
    protocol: fp.protocol,
    product: fp.product || void 0,
    banner: fp.banner || void 0,
    technologies
  }));
  const credentialResults = await runCredentialTests(targets, {
    concurrency: 2,
    timeoutMs: 8e3,
    maxCredsPerTarget: 5,
    engagementId: options?.engagementId,
    operatorId: options?.operatorId
  });
  for (const fp of fingerprintResults) {
    const targetKey = `${fp.host}:${fp.port}`;
    const targetResults = credentialResults.byTarget.get(targetKey) || [];
    const successfulCreds = targetResults.filter((r) => r.status === "success");
    if (successfulCreds.length > 0) {
      fp.securityFlags.defaultCredentials = true;
      fp.metadata.confirmedDefaultCredentials = successfulCreds.map((r) => ({
        vendor: r.credential.vendor,
        product: r.credential.product,
        username: r.credential.username,
        accessLevel: r.confirmedAccess,
        protocol: r.credential.protocol
      }));
      for (const cred of successfulCreds) {
        fp.riskIndicators.push({
          severity: "critical",
          title: `Default Credentials Confirmed: ${cred.credential.vendor} ${cred.credential.product}`,
          description: `Successfully authenticated with default credentials (${cred.credential.username}:***) via ${cred.credential.protocol}. Access level: ${cred.confirmedAccess || "unknown"}.`,
          cweId: "CWE-798",
          mitreId: "T1078.001"
        });
      }
    }
    const allMatched = getCredentialsForService({
      host: fp.host,
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product || void 0,
      banner: fp.banner || void 0,
      technologies
    });
    if (allMatched.length > 0) {
      fp.metadata.matchedOemCredentials = allMatched.map((c) => ({
        vendor: c.vendor,
        product: c.product,
        protocol: c.protocol,
        username: c.username,
        password: c.password,
        accessLevel: c.accessLevel,
        notes: c.notes
      }));
    }
  }
  return { credentialResults, enrichedFingerprints: fingerprintResults };
}
async function getCredentialsForZapPlaybook(technologies) {
  const results = [];
  const seen = /* @__PURE__ */ new Set();
  for (const tech of technologies) {
    const matches = await matchCredentialsForTechnology({ name: tech });
    for (const m of matches) {
      if (["https", "http", "web_admin"].includes(m.protocol)) {
        const key = `${m.username}:${m.password}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            username: m.username,
            password: m.password,
            vendor: m.vendor,
            product: m.product
          });
        }
      }
    }
  }
  return results;
}
var PROTOCOL_TESTERS;
var init_credential_tester = __esm({
  "server/lib/credential-tester.ts"() {
    init_oem_default_creds();
    PROTOCOL_TESTERS = {
      ssh: testSshCredential,
      ftp: testFtpCredential,
      telnet: testTelnetCredential,
      redis: testRedisCredential,
      mysql: testMysqlCredential,
      postgresql: testMysqlCredential,
      // Same banner-level approach
      mssql: testMysqlCredential,
      https: testHttpCredential,
      http: testHttpCredential,
      web_admin: testHttpCredential
    };
  }
});
init_credential_tester();
export {
  enrichFingerprintsWithCredentialTests,
  getCredentialsForService,
  getCredentialsForZapPlaybook,
  runCredentialTests,
  testCredential
};
