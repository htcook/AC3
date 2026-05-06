import {
  init_oem_default_creds,
  matchCredentialsForAsset
} from "./chunk-YBXDAJGB.js";
import {
  FIPS_SSH_ALGORITHMS,
  init_fips_ssh
} from "./chunk-SD56WPOS.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scan-server-executor.ts
import { Client as SSHClient } from "ssh2";
import { createRequire } from "module";
async function getScanServerConfig() {
  const host = ENV.SCAN_SERVER_HOST;
  const user = ENV.SCAN_SERVER_USER || "root";
  const sshKey = process.env.SCAN_SERVER_SSH_KEY ?? "";
  if (!host) throw new Error("SCAN_SERVER_HOST not configured");
  if (cachedSshKey) return { host, username: user, privateKey: cachedSshKey };
  let fixedKey = null;
  if (sshKey) {
    if (sshKey.startsWith("http://") || sshKey.startsWith("https://")) {
      try {
        const resp = await fetch(sshKey);
        if (resp.ok) fixedKey = await resp.text();
      } catch {
      }
    } else if (!sshKey.startsWith("-----")) {
      fixedKey = Buffer.from(sshKey, "base64").toString("utf8");
    } else if (sshKey.includes("\\n")) {
      fixedKey = sshKey.split("\\n").join("\n");
    } else {
      fixedKey = sshKey;
    }
  }
  if (fixedKey) {
    const parsed = sshUtils.parseKey(fixedKey);
    if (parsed instanceof Error) {
      console.log(`[ScanServer] Env SSH key parse failed (${parsed.message}), trying S3 RSA fallback...`);
      fixedKey = null;
    } else {
      console.log(`[ScanServer] Using env SSH key (type: ${parsed.type}, comment: ${parsed.comment || "none"})`);
    }
  }
  if (!fixedKey) {
    console.log("[ScanServer] Downloading RSA key from S3 fallback...");
    try {
      const resp = await fetch(SCAN_SERVER_KEY_URL);
      if (resp.ok) {
        fixedKey = await resp.text();
        console.log("[ScanServer] RSA key downloaded successfully");
      }
    } catch (e) {
      console.error("[ScanServer] Failed to download RSA key:", e);
    }
  }
  if (!fixedKey) throw new Error("SCAN_SERVER_SSH_KEY not configured and fallback download failed");
  cachedSshKey = fixedKey;
  return { host, username: user, privateKey: fixedKey };
}
function resetPoolIdleTimer() {
  if (poolIdleTimer) clearTimeout(poolIdleTimer);
  poolIdleTimer = setTimeout(() => {
    if (pooledConn) {
      pooledConn.end();
      pooledConn = null;
      pooledConnReady = false;
    }
  }, POOL_IDLE_TIMEOUT);
}
function cleanupSSHPool() {
  if (poolIdleTimer) {
    clearTimeout(poolIdleTimer);
    poolIdleTimer = null;
  }
  if (pooledConn) {
    try {
      pooledConn.end();
      console.log("[ScanServer] SSH pool connection closed (graceful shutdown)");
    } catch {
    }
    pooledConn = null;
    pooledConnReady = false;
  }
}
async function getPooledConnection() {
  if (pooledConn && pooledConnReady) {
    resetPoolIdleTimer();
    return pooledConn;
  }
  if (pooledConn) {
    try {
      pooledConn.end();
    } catch {
    }
    pooledConn = null;
    pooledConnReady = false;
  }
  const config = await getScanServerConfig();
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    const readyTimer = setTimeout(() => {
      conn.end();
      reject(new Error("SSH pool connection timed out after 20s"));
    }, 2e4);
    conn.on("ready", () => {
      clearTimeout(readyTimer);
      pooledConn = conn;
      pooledConnReady = true;
      resetPoolIdleTimer();
      resolve(conn);
    }).on("error", (err) => {
      clearTimeout(readyTimer);
      pooledConn = null;
      pooledConnReady = false;
      reject(new Error(`SSH pool connection error: ${err.message}`));
    }).on("close", () => {
      pooledConn = null;
      pooledConnReady = false;
    }).connect({
      host: config.host,
      port: 22,
      username: config.username,
      privateKey: config.privateKey,
      readyTimeout: 2e4,
      keepaliveInterval: 1e4,
      algorithms: FIPS_SSH_ALGORITHMS
    });
  });
}
async function executeSSHPooled(command, timeoutMs) {
  const conn = await getPooledConnection();
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      reject(new Error(`SSH command timed out after ${timeoutMs / 1e3}s`));
    }, timeoutMs);
    conn.exec(command, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        return reject(err);
      }
      stream.on("close", (code) => {
        clearTimeout(timer);
        resetPoolIdleTimer();
        if (!timedOut) {
          resolve({ stdout, stderr, exitCode: code || 0 });
        }
      });
      stream.on("data", (data) => {
        stdout += data.toString();
      });
      stream.stderr.on("data", (data) => {
        stderr += data.toString();
      });
    });
  });
}
function getSSHRetryMetrics() {
  return { ...sshRetryMetrics };
}
function isRetryableSSHError(error) {
  const msg = typeof error === "string" ? error : error.message;
  return SSH_RETRY_CONFIG.retryablePatterns.some((pattern) => msg.includes(pattern));
}
async function sshSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function executeSSHWithRetry(command, timeoutSeconds, usePool = true) {
  let lastError = null;
  for (let attempt = 0; attempt <= SSH_RETRY_CONFIG.maxRetries; attempt++) {
    try {
      if (usePool) {
        return await executeSSHPooled(command, timeoutSeconds * 1e3);
      } else {
        return await executeViaChildProcessSSH(command, timeoutSeconds);
      }
    } catch (err) {
      lastError = err;
      if (attempt < SSH_RETRY_CONFIG.maxRetries && isRetryableSSHError(err)) {
        sshRetryMetrics.totalRetries++;
        const delay = SSH_RETRY_CONFIG.baseDelayMs * Math.pow(SSH_RETRY_CONFIG.backoffMultiplier, attempt);
        console.warn(`[ScanServer] SSH attempt ${attempt + 1}/${SSH_RETRY_CONFIG.maxRetries + 1} failed: ${err.message}. Retrying in ${delay}ms...`);
        if (pooledConn) {
          try {
            pooledConn.end();
          } catch {
          }
          pooledConn = null;
          pooledConnReady = false;
        }
        await sshSleep(delay);
        continue;
      }
      if (attempt >= SSH_RETRY_CONFIG.maxRetries) {
        sshRetryMetrics.exhaustedRetries++;
        console.error(`[ScanServer] SSH retries exhausted after ${attempt + 1} attempts: ${err.message}`);
      }
      throw err;
    }
  }
  sshRetryMetrics.successAfterRetry++;
  throw lastError || new Error("SSH retry logic error");
}
async function executeTool(config) {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();
  if (!ALLOWED_TOOLS.has(tool)) {
    console.warn(`[ScanServer] Tool "${tool}" blocked by whitelist. Allowed: ${[...ALLOWED_TOOLS].join(", ")}`);
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: `Tool "${tool}" is not in the allowed tools whitelist`,
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: `Tool "${tool}" not allowed`
    };
  }
  console.log(`[ScanServer] executeTool: tool=${tool}, timeout=${timeoutSeconds}s, target=${config.target || "N/A"}, args=${String(args).substring(0, 150)}`);
  try {
    const { executeToolViaHttp } = await import("./do-scan-api-FZYOCIUA.js");
    const httpResult = await executeToolViaHttp(config);
    console.log(`[ScanServer] HTTP API result: tool=${tool}, exitCode=${httpResult.exitCode}, timedOut=${httpResult.timedOut}, duration=${httpResult.durationMs}ms, stdout=${httpResult.stdout?.substring(0, 100) || "(empty)"}`);
    return httpResult;
  } catch (httpImportErr) {
    console.warn(`[ScanServer] HTTP API module unavailable (${httpImportErr.message}), using direct SSH with retry`);
  }
  const prefix = sudo ? "sudo " : "";
  const command = `${prefix}${tool} ${args} 2>&1`;
  console.log(`[ScanServer] SSH fallback: ${command.substring(0, 150)}`);
  try {
    const result = await executeSSHWithRetry(command, timeoutSeconds, false);
    if (sshRetryMetrics.totalRetries > 0) sshRetryMetrics.successAfterRetry++;
    console.log(`[ScanServer] SSH result: tool=${tool}, exitCode=${result.exitCode}, duration=${Date.now() - startTime}ms, stdout=${result.stdout?.substring(0, 100) || "(empty)"}`);
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: result.stdout.slice(0, 5e5),
      stderr: result.stderr.slice(0, 5e4),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false
    };
  } catch (err) {
    const timedOut = err.message.includes("timed out");
    console.error(`[ScanServer] SSH error: tool=${tool}, timedOut=${timedOut}, error=${err.message.substring(0, 200)}`);
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: err.message,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut,
      error: err.message
    };
  }
}
async function executeRawCommand(command, timeoutSeconds = 300) {
  const startTime = Date.now();
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api-FZYOCIUA.js");
    return await executeRawCommandViaHttp(command, timeoutSeconds);
  } catch (httpImportErr) {
    console.warn(`[ScanServer] HTTP API module unavailable for raw command, using direct SSH`);
  }
  try {
    const result = await executeSSHWithRetry(command, timeoutSeconds, false);
    if (sshRetryMetrics.totalRetries > 0) sshRetryMetrics.successAfterRetry++;
    return {
      tool: "raw",
      command,
      stdout: result.stdout.slice(0, 5e5),
      stderr: result.stderr.slice(0, 5e4),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false
    };
  } catch (err) {
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: err.message,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: err.message.includes("timed out"),
      error: err.message
    };
  }
}
async function executeViaChildProcessSSH(command, timeoutSeconds) {
  console.log(`[ChildProcessSSH] START: timeout=${timeoutSeconds}s cmd=${command.slice(0, 80)}...`);
  const { spawn } = await import("child_process");
  const { writeFile, unlink } = await import("fs/promises");
  const config = await getScanServerConfig();
  const keyPath = `/tmp/.scan_key_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  await writeFile(keyPath, config.privateKey, { mode: 384 });
  const MAX_OUTPUT = 512 * 1024;
  return new Promise((resolve, reject) => {
    const args = [
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      "LogLevel=ERROR",
      "-o",
      `ConnectTimeout=15`,
      "-o",
      "ServerAliveInterval=15",
      "-o",
      "ServerAliveCountMax=3",
      "-i",
      keyPath,
      `${config.username}@${config.host}`,
      command
    ];
    const child = spawn("ssh", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdoutBuf = "";
    let stderrBuf = "";
    let stdoutCapped = false;
    let stderrCapped = false;
    let resolved = false;
    child.stdout.on("data", (chunk) => {
      if (stdoutCapped) return;
      const str = chunk.toString("utf8");
      if (stdoutBuf.length + str.length > MAX_OUTPUT) {
        stdoutBuf += str.slice(0, MAX_OUTPUT - stdoutBuf.length);
        stdoutBuf += "\n[OUTPUT TRUNCATED]";
        stdoutCapped = true;
      } else {
        stdoutBuf += str;
      }
    });
    child.stderr.on("data", (chunk) => {
      if (stderrCapped) return;
      const str = chunk.toString("utf8");
      if (stderrBuf.length + str.length > MAX_OUTPUT) {
        stderrBuf += str.slice(0, MAX_OUTPUT - stderrBuf.length);
        stderrCapped = true;
      } else {
        stderrBuf += str;
      }
    });
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 5e3);
        unlink(keyPath).catch(() => {
        });
        resolve({
          stdout: stdoutBuf,
          stderr: stderrBuf + "\n[TIMED OUT]",
          exitCode: -1
        });
      }
    }, timeoutSeconds * 1e3);
    child.on("close", (code) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        unlink(keyPath).catch(() => {
        });
        console.log(`[ChildProcessSSH] DONE: exit=${code} stdout=${stdoutBuf.length}b stderr=${stderrBuf.length}b`);
        resolve({
          stdout: stdoutBuf,
          stderr: stderrBuf,
          exitCode: code ?? -1
        });
      }
    });
    child.on("error", (err) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        unlink(keyPath).catch(() => {
        });
        resolve({
          stdout: stdoutBuf,
          stderr: err.message,
          exitCode: -1
        });
      }
    });
  });
}
async function checkScanServerStatus() {
  try {
    const result = await executeSSHWithRetry("cat /opt/tool-manifest.json 2>/dev/null && echo '---HEALTH---' && bash /opt/health-check.sh 2>/dev/null", 15, true);
    const parts = result.stdout.split("---HEALTH---");
    let tools = {};
    try {
      const manifest = JSON.parse(parts[0].trim());
      for (const [name, info] of Object.entries(manifest.tools || {})) {
        tools[name] = { installed: true, path: info.path };
      }
    } catch {
    }
    let health = {};
    try {
      health = JSON.parse((parts[1] || "").trim());
    } catch {
    }
    return {
      connected: true,
      tools,
      uptime: health.uptime,
      diskFree: health.disk_free,
      memoryFree: health.memory_free
    };
  } catch (err) {
    return {
      connected: false,
      tools: {},
      error: err.message
    };
  }
}
async function getScanServerConfigForScanForge() {
  const config = await getScanServerConfig();
  return {
    host: config.host,
    port: 22,
    username: config.username,
    privateKey: config.privateKey
  };
}
async function suggestToolCommands(asset) {
  const target = asset.ip || asset.hostname || "";
  const hydraTarget = asset.hostname || asset.ip || "";
  const commands = [];
  const portList = asset.ports.map((p) => p.port).join(",");
  const webPorts = asset.ports.filter(
    (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3, 9090].includes(p.port)
  );
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.port === 8444 || wp.port === 8445 || wp.port === 8447 || wp.port === 9443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "raw",
        args: `echo '${url}' | httpx -silent -nc -json -follow-redirects -tech-detect -status-code -title -web-server -content-length -content-type`,
        purpose: `HTTP probe and tech detection on ${url}`,
        priority: 1
      });
      commands.push({
        tool: "raw",
        args: `echo '${url}' | nuclei -jsonl -nc -timeout 10 -retries 1 -rate-limit 100 -silent -tags exposure,misconfig,tech,xss,sqli,lfi,ssrf,cve,rce,traversal -severity info,low,medium,high,critical -concurrency 5`,
        purpose: `CVE/vulnerability template scan on ${url}`,
        priority: 1
      });
      const niktoSslFlag = isHttps ? " -ssl" : "";
      commands.push({
        tool: "nikto",
        args: `-h ${url}${niktoSslFlag} -Tuning 1234567890abc -maxtime 300`,
        purpose: `Web vulnerability scan on ${url}`,
        priority: 1
      });
      commands.push({
        tool: "gobuster",
        args: `dir -u ${url} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error`,
        purpose: `Directory brute-force on ${url}`,
        priority: 2
      });
    }
  }
  if (asset.technologies && asset.technologies.length > 0) {
    try {
      const oemMatches = await matchCredentialsForAsset(asset.technologies);
      for (const svc of oemMatches) {
        const credPairs = svc.credentials;
        if (credPairs.length === 0) continue;
        const matchingPort = svc.port ? asset.ports.find((p) => p.port === svc.port) : null;
        if (svc.port && !matchingPort) continue;
        const protocolToHydra = {
          ssh: "ssh",
          telnet: "telnet",
          ftp: "ftp",
          mysql: "mysql",
          postgres: "postgres",
          mssql: "mssql",
          rdp: "rdp",
          http: "http-form-post",
          https: "https-form-post",
          web_admin: "http-form-post",
          http_basic: "http-get",
          https_basic: "https-get",
          snmp: "snmp",
          ldap: "ldap2",
          oracle: "oracle-listener"
        };
        const hydraModule = protocolToHydra[credPairs[0].protocol] || credPairs[0].protocol;
        const port = svc.port || matchingPort?.port;
        if (!port) continue;
        for (const cred of credPairs) {
          const passArg = cred.password === "" ? `-e n` : `-p '${cred.password}'`;
          if (hydraModule === "http-form-post" || hydraModule === "https-form-post") {
            const loginPaths = ["/login", "/admin/login", "/auth/login", "/api/auth/login", "/signin"];
            const formVariants = [
              { fields: "username=^USER^&password=^PASS^", failStr: "invalid|incorrect|failed|error|denied|wrong" },
              { fields: "email=^USER^&password=^PASS^", failStr: "invalid|incorrect|failed|error|denied|wrong" },
              { fields: "user=^USER^&pass=^PASS^", failStr: "invalid|incorrect|failed|error|denied|wrong" }
            ];
            commands.push({
              tool: "hydra",
              args: `-l '${cred.username}' ${passArg} -s ${port} -t 4 -f -V ${hydraTarget} ${hydraModule} '${loginPaths[0]}:${formVariants[0].fields}:F=${formVariants[0].failStr}'`,
              purpose: `[OEM Default] ${cred.vendor} ${cred.product} \u2014 ${cred.username}:${cred.password || "(empty)"} via HTTP form on port ${port}`,
              priority: 3
            });
          } else {
            commands.push({
              tool: "hydra",
              args: `-l '${cred.username}' ${passArg} -s ${port} -t 4 -f -V ${hydraTarget} ${hydraModule}`,
              purpose: `[OEM Default] ${cred.vendor} ${cred.product} \u2014 ${cred.username}:${cred.password || "(empty)"} on port ${port}`,
              priority: 3
            });
          }
        }
      }
    } catch (e) {
    }
  }
  if (webPorts.length > 0) {
    const KNOWN_WEB_APP_CREDS = [
      {
        pattern: /dvwa/i,
        loginPath: "/login.php",
        formData: "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed",
        username: "admin",
        password: "password",
        appName: "DVWA"
      },
      {
        pattern: /juice.?shop/i,
        loginPath: "/rest/user/login",
        formData: '/rest/user/login:{"email":"^USER^","password":"^PASS^"}:Invalid',
        username: "admin@juice-sh.op",
        password: "admin123",
        appName: "Juice Shop"
      },
      {
        pattern: /webgoat/i,
        loginPath: "/WebGoat/login",
        formData: "/WebGoat/login:username=^USER^&password=^PASS^:Invalid",
        username: "guest",
        password: "guest",
        appName: "WebGoat"
      },
      {
        pattern: /bwapp/i,
        loginPath: "/login.php",
        formData: "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid",
        username: "bee",
        password: "bug",
        appName: "bWAPP"
      },
      {
        pattern: /mutillidae/i,
        loginPath: "/index.php?page=login.php",
        formData: "/index.php?page=login.php:username=^USER^&password=^PASS^&login-php-submit-button=Login:Authentication Error",
        username: "admin",
        password: "admin",
        appName: "Mutillidae"
      },
      {
        pattern: /crapi/i,
        loginPath: "/identity/api/auth/login",
        formData: '/identity/api/auth/login:{"email":"^USER^","password":"^PASS^"}:Invalid',
        username: "victim@example.com",
        password: "Cr4p1!",
        appName: "crAPI"
      }
    ];
    const hostLower = (asset.hostname || "").toLowerCase();
    const techNames = (asset.technologies || []).map((t) => (t.name || "").toLowerCase()).join(" ");
    const matchStr = `${hostLower} ${techNames}`;
    for (const wp of webPorts) {
      const scheme = wp.port === 443 || wp.port === 8443 ? "https" : "http";
      for (const app of KNOWN_WEB_APP_CREDS) {
        if (app.pattern.test(matchStr)) {
          const hydraModule = scheme === "https" ? "https-form-post" : "http-form-post";
          commands.push({
            tool: "hydra",
            args: `-l '${app.username}' -p '${app.password}' -s ${wp.port} -t 4 -f -V ${hydraTarget} ${hydraModule} '${app.formData}'`,
            purpose: `[Known App] ${app.appName} HTTP form login \u2014 ${app.username}:${app.password} on port ${wp.port}`,
            priority: 3
          });
        }
      }
      commands.push({
        tool: "hydra",
        args: `-l admin -P /opt/SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt -s ${wp.port} -t 4 -f -V ${hydraTarget} ${scheme === "https" ? "https-form-post" : "http-form-post"} '/login:username=^USER^&password=^PASS^:incorrect'`,
        purpose: `HTTP form credential testing (common passwords) on port ${wp.port}`,
        priority: 3
      });
    }
  }
  const sshPorts = asset.ports.filter((p) => p.service === "ssh" || p.port === 22);
  if (sshPorts.length > 0) {
    for (const sp of sshPorts) {
      commands.push({
        tool: "hydra",
        args: `-l admin -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s ${sp.port} -t 4 -f -V ${hydraTarget} ssh`,
        purpose: `SSH credential testing (generic wordlist) on port ${sp.port}`,
        priority: 3
      });
    }
  }
  const smbPorts = asset.ports.filter(
    (p) => ["microsoft-ds", "netbios-ssn", "smb"].includes(p.service) || [139, 445].includes(p.port)
  );
  if (smbPorts.length > 0) {
    commands.push({
      tool: "enum4linux",
      args: `-a ${target}`,
      purpose: `SMB/NetBIOS enumeration`,
      priority: 2
    });
    commands.push({
      tool: "smbclient",
      args: `-L //${target} -N`,
      purpose: `List SMB shares (anonymous)`,
      priority: 2
    });
  }
  const ldapPorts = asset.ports.filter(
    (p) => ["ldap", "ldaps"].includes(p.service) || [389, 636].includes(p.port)
  );
  if (ldapPorts.length > 0) {
    commands.push({
      tool: "ldapsearch",
      args: `-x -H ldap://${target} -b "" -s base namingContexts`,
      purpose: `LDAP anonymous enumeration`,
      priority: 2
    });
  }
  const snmpPorts = asset.ports.filter(
    (p) => p.service === "snmp" || p.port === 161
  );
  if (snmpPorts.length > 0) {
    commands.push({
      tool: "onesixtyone",
      args: `${target} public private`,
      purpose: `SNMP community string brute-force`,
      priority: 2
    });
  }
  const dnsPorts = asset.ports.filter(
    (p) => p.service === "domain" || p.port === 53
  );
  if (dnsPorts.length > 0 && asset.hostname) {
    commands.push({
      tool: "dig",
      args: `@${target} ${asset.hostname} any +noall +answer`,
      purpose: `DNS enumeration`,
      priority: 2
    });
    commands.push({
      tool: "dig",
      args: `@${target} ${asset.hostname} axfr`,
      purpose: `DNS zone transfer attempt`,
      priority: 3
    });
  }
  const ftpPorts = asset.ports.filter(
    (p) => p.service === "ftp" || p.port === 21
  );
  if (ftpPorts.length > 0) {
    commands.push({
      tool: "hydra",
      args: `-l anonymous -p anonymous -s 21 -t 4 -f ${target} ftp`,
      purpose: `FTP anonymous login test`,
      priority: 2
    });
  }
  const dbPorts = asset.ports.filter(
    (p) => ["mysql", "postgresql"].includes(p.service) || [3306, 5432].includes(p.port)
  );
  if (dbPorts.length > 0) {
    for (const dp of dbPorts) {
      const proto = dp.port === 5432 ? "postgres" : "mysql";
      commands.push({
        tool: "hydra",
        args: `-l root -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s ${dp.port} -t 4 -f ${target} ${proto}`,
        purpose: `${proto} credential testing (generic wordlist) on port ${dp.port}`,
        priority: 3
      });
    }
  }
  const rdpPorts = asset.ports.filter(
    (p) => p.service === "ms-wbt-server" || p.port === 3389
  );
  if (rdpPorts.length > 0) {
    commands.push({
      tool: "hydra",
      args: `-l administrator -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s 3389 -t 4 -f ${target} rdp`,
      purpose: `RDP credential testing (generic wordlist)`,
      priority: 3
    });
  }
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "katana",
        args: `-u ${url} -d 3 -jc -kf -json -silent -headless -timeout 15 -rate-limit 10 -crawl-duration 300s`,
        purpose: `JS-aware web crawling on ${url} \u2014 discovers endpoints hidden behind JavaScript rendering`,
        priority: 1
      });
    }
  }
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "feroxbuster",
        args: `-u ${url} -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 50 --depth 3 --timeout 10 --status-codes 200,204,301,302,307,308,401,403,405 -x php,asp,aspx,jsp,html,js --json --quiet --no-state --auto-calibration --dont-scan /logout`,
        purpose: `Recursive content discovery on ${url} \u2014 finds hidden directories, files, and endpoints`,
        priority: 2
      });
    }
  }
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const baseUrl = `${scheme}://${target}:${wp.port}`;
      const apiPaths = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/api-docs.json",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/redoc",
        "/graphql",
        "/graphiql",
        "/playground",
        "?wsdl",
        "/service?wsdl",
        "/actuator",
        "/actuator/info",
        "/actuator/env",
        "/actuator/health",
        "/.well-known/openapi"
      ];
      const probeUrls = apiPaths.map((p) => `${baseUrl}${p}`).join(" ");
      commands.push({
        tool: "raw",
        args: `for url in ${probeUrls}; do code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$url"); if [ "$code" != "000" ] && [ "$code" != "404" ] && [ "$code" != "503" ]; then echo "$code $url"; fi; done`,
        purpose: `API specification discovery on ${baseUrl} \u2014 probes for Swagger, OpenAPI, GraphQL, WSDL, and Spring Actuator endpoints`,
        priority: 2
      });
      commands.push({
        tool: "raw",
        args: `curl -s -m 10 -X POST ${baseUrl}/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}types{name kind}}}"}'`,
        purpose: `GraphQL introspection probe on ${baseUrl}/graphql`,
        priority: 2
      });
    }
  }
  if (webPorts.length > 0 && asset.hostname) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "arjun",
        args: `-u ${url} -m GET -t 10 --timeout 15 -oJ /dev/stdout --passive`,
        purpose: `Hidden parameter discovery on ${url} \u2014 finds unlinked GET parameters`,
        priority: 2
      });
      commands.push({
        tool: "arjun",
        args: `-u ${url} -m POST -t 10 --timeout 15 -oJ /dev/stdout --passive`,
        purpose: `Hidden parameter discovery on ${url} \u2014 finds unlinked POST parameters`,
        priority: 2
      });
    }
    commands.push({
      tool: "paramspider",
      args: `-d ${asset.hostname} --exclude css,js,png,jpg,gif,svg,woff,ttf,ico,pdf --level high -o /dev/stdout`,
      purpose: `Web archive parameter mining for ${asset.hostname} \u2014 discovers historical URL parameters`,
      priority: 2
    });
  }
  const tlsPorts = asset.ports.filter(
    (p) => p.service === "https" || p.service === "ssl" || [443, 8443, 993, 995, 465, 636].includes(p.port)
  );
  if (tlsPorts.length > 0) {
    for (const tp of tlsPorts) {
      commands.push({
        tool: "testssl.sh",
        args: `--jsonfile - --quiet --color 0 --sneaky -U -p -S ${target}:${tp.port}`,
        purpose: `TLS vulnerability testing on ${target}:${tp.port} \u2014 checks for Heartbleed, POODLE, ROBOT, DROWN, FREAK, BEAST, weak ciphers`,
        priority: 2
      });
    }
  }
  if (webPorts.length > 0 && asset.hostname) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "ffuf",
        args: `-w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u ${url} -H "Host: FUZZ.${asset.hostname}" -mc 200,204,301,302,307,308,401,403 -json -s -ac`,
        purpose: `Virtual host enumeration on ${url} \u2014 discovers hidden vhosts sharing the same IP`,
        priority: 3
      });
    }
  }
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === "https" || wp.service === "ssl";
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;
      commands.push({
        tool: "wafw00f",
        args: `${url} -o - -a`,
        purpose: `WAF fingerprinting on ${url} \u2014 identifies web application firewalls for evasion planning`,
        priority: 3
      });
    }
  }
  commands.sort((a, b) => a.priority - b.priority);
  return commands;
}
var _require, sshUtils, ALLOWED_TOOLS, cachedSshKey, SCAN_SERVER_KEY_URL, pooledConn, pooledConnReady, poolIdleTimer, POOL_IDLE_TIMEOUT, SSH_RETRY_CONFIG, sshRetryMetrics;
var init_scan_server_executor = __esm({
  "server/lib/scan-server-executor.ts"() {
    init_env();
    init_oem_default_creds();
    init_fips_ssh();
    _require = createRequire(import.meta.url);
    sshUtils = _require("ssh2").utils;
    ALLOWED_TOOLS = /* @__PURE__ */ new Set([
      "scanforge-discovery",
      "nuclei",
      "nikto",
      "gobuster",
      "hydra",
      "httpx",
      "naabu",
      "subfinder",
      "enum4linux",
      "smbclient",
      "ldapsearch",
      "snmpwalk",
      "nbtscan",
      "onesixtyone",
      "dig",
      "whois",
      "sqlmap",
      "wfuzz",
      "crackmapexec",
      "masscan",
      "curl",
      "wget",
      "cat",
      "head",
      "tail",
      "grep",
      // Web application & SSL scanning tools
      "ffuf",
      "sslscan",
      "whatweb",
      "testssl",
      "wpscan",
      "zap-cli",
      "zap.sh",
      // OWASP ZAP (via Docker or direct install)
      "zap",
      "docker",
      "zaproxy",
      // Cloud storage & misconfiguration enumeration tools
      "cloud_enum",
      "s3scanner",
      "trufflehog",
      "aws",
      // Packet capture, analysis & manipulation tools
      "tcpdump",
      "tshark",
      "editcap",
      "mergecap",
      "capinfos",
      // Scapy packet crafting (via Python)
      "python3",
      "scapy",
      // Advanced injection & XSS testing tools
      "xsstrike",
      "dalfox",
      // Command injection & template injection tools
      "commix",
      "tplmap",
      // Service fingerprinting, SSH audit, and web crawling
      "nerva",
      "ssh-audit",
      "katana",
      // Recursive content discovery & web fuzzing (Audit R4, R12)
      "feroxbuster",
      "dirb",
      "dirsearch",
      // Parameter discovery (Audit R7)
      "arjun",
      "paramspider",
      // WAF fingerprinting (Audit R15)
      "wafw00f",
      // TLS vulnerability testing (Audit R8)
      "testssl.sh",
      // Screenshot capture
      "chromium",
      "chromium-browser",
      "google-chrome",
      "puppeteer",
      // Allow reading tool manifest and health check
      "bash",
      "sh"
    ]);
    cachedSshKey = null;
    SCAN_SERVER_KEY_URL = process.env.SCAN_SERVER_KEY_URL || "https://files.manuscdn.com/user_upload_by_module/session_file/310419663028432609/hHJfIBSNDxDiefRC";
    pooledConn = null;
    pooledConnReady = false;
    poolIdleTimer = null;
    POOL_IDLE_TIMEOUT = 6e4;
    SSH_RETRY_CONFIG = {
      maxRetries: 3,
      baseDelayMs: 2e3,
      // 2s → 4s → 8s exponential backoff
      backoffMultiplier: 2,
      /** Error patterns that indicate a transient SSH/network issue worth retrying */
      retryablePatterns: [
        "ECONNREFUSED",
        "ECONNRESET",
        "ETIMEDOUT",
        "EHOSTUNREACH",
        "ENETUNREACH",
        "SSH connection error",
        "SSH pool connection error",
        "SSH pool connection timed out",
        "SSH command timed out",
        "socket hang up",
        "Connection reset",
        "read ECONNRESET",
        "connect ECONNREFUSED",
        "Channel open failure",
        "Keepalive timeout",
        "Client-side network socket disconnected"
      ]
    };
    sshRetryMetrics = {
      totalRetries: 0,
      successAfterRetry: 0,
      exhaustedRetries: 0
    };
  }
});

export {
  getScanServerConfig,
  cleanupSSHPool,
  getSSHRetryMetrics,
  executeTool,
  executeRawCommand,
  executeViaChildProcessSSH,
  checkScanServerStatus,
  getScanServerConfigForScanForge,
  suggestToolCommands,
  init_scan_server_executor
};
