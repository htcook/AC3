import {
  enforceScope,
  init_scope_guard
} from "./chunk-JCJFQN2U.js";
import {
  FIPS_SSH_ALGORITHMS,
  init_fips_ssh
} from "./chunk-SD56WPOS.js";

// server/lib/amass-engine.ts
init_scope_guard();
init_fips_ssh();
import crypto from "crypto";
import { Client as SSHClient } from "ssh2";
import fs from "fs";
var BUILT_IN_WORDLIST = [
  // Infrastructure
  "www",
  "mail",
  "ftp",
  "smtp",
  "pop",
  "imap",
  "ns1",
  "ns2",
  "ns3",
  "dns",
  "dns1",
  "dns2",
  "mx",
  "mx1",
  "mx2",
  "relay",
  "gateway",
  "proxy",
  // Web services
  "api",
  "app",
  "web",
  "portal",
  "admin",
  "panel",
  "dashboard",
  "console",
  "login",
  "auth",
  "sso",
  "oauth",
  "accounts",
  "my",
  "account",
  // Development & CI/CD
  "dev",
  "staging",
  "stage",
  "test",
  "testing",
  "qa",
  "uat",
  "sandbox",
  "demo",
  "beta",
  "alpha",
  "preview",
  "canary",
  "ci",
  "cd",
  "build",
  "jenkins",
  "gitlab",
  "github",
  "bitbucket",
  "bamboo",
  "drone",
  "argo",
  // Cloud & containers
  "cloud",
  "aws",
  "azure",
  "gcp",
  "k8s",
  "kubernetes",
  "docker",
  "registry",
  "harbor",
  "ecr",
  "gcr",
  "acr",
  "s3",
  "cdn",
  "static",
  "assets",
  "media",
  // Databases & storage
  "db",
  "database",
  "mysql",
  "postgres",
  "postgresql",
  "mongo",
  "mongodb",
  "redis",
  "elastic",
  "elasticsearch",
  "kibana",
  "grafana",
  "influx",
  "minio",
  "ceph",
  "nfs",
  "backup",
  "backups",
  "storage",
  // Monitoring & logging
  "monitor",
  "monitoring",
  "nagios",
  "zabbix",
  "prometheus",
  "alertmanager",
  "log",
  "logs",
  "logging",
  "splunk",
  "elk",
  "graylog",
  "sentry",
  "datadog",
  // Security
  "vpn",
  "openvpn",
  "wireguard",
  "firewall",
  "waf",
  "ids",
  "ips",
  "siem",
  "vault",
  "secrets",
  "cert",
  "certs",
  "pki",
  "ca",
  // Communication
  "chat",
  "slack",
  "teams",
  "meet",
  "zoom",
  "webex",
  "jitsi",
  "wiki",
  "confluence",
  "docs",
  "documentation",
  "help",
  "support",
  "jira",
  "ticket",
  "tickets",
  "helpdesk",
  "servicedesk",
  // Network
  "intranet",
  "internal",
  "corp",
  "corporate",
  "office",
  "remote",
  "bastion",
  "jump",
  "jumpbox",
  "ssh",
  "rdp",
  "vnc",
  "telnet",
  "switch",
  "router",
  "fw",
  "lb",
  "loadbalancer",
  "haproxy",
  "nginx",
  // Services
  "crm",
  "erp",
  "hr",
  "payroll",
  "finance",
  "billing",
  "payment",
  "shop",
  "store",
  "ecommerce",
  "cart",
  "checkout",
  "order",
  "orders",
  "blog",
  "cms",
  "wordpress",
  "wp",
  "drupal",
  "joomla",
  // APIs & microservices
  "api-v1",
  "api-v2",
  "api-gateway",
  "graphql",
  "rest",
  "grpc",
  "service",
  "services",
  "microservice",
  "ms",
  "svc",
  // Email
  "webmail",
  "owa",
  "exchange",
  "autodiscover",
  "autoconfig",
  "spam",
  "antispam",
  "dkim",
  "spf",
  "dmarc",
  // Misc
  "status",
  "health",
  "ping",
  "info",
  "about",
  "contact",
  "download",
  "downloads",
  "upload",
  "uploads",
  "files",
  "file",
  "img",
  "images",
  "image",
  "video",
  "videos",
  "stream",
  "search",
  "analytics",
  "metrics",
  "report",
  "reports",
  "old",
  "legacy",
  "archive",
  "temp",
  "tmp",
  "cache",
  "m",
  "mobile",
  "wap",
  "touch"
];
function executeSSHCommand(server, command, timeoutMs) {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      conn.end();
      reject(new Error(`SSH command timed out after ${timeoutMs / 1e3}s`));
    }, timeoutMs);
    let privateKey;
    if (server.privateKey) {
      privateKey = server.privateKey;
    } else if (server.privateKeyPath) {
      try {
        privateKey = fs.readFileSync(server.privateKeyPath);
      } catch (err) {
        clearTimeout(timer);
        reject(new Error(`Cannot read SSH key: ${err.message}`));
        return;
      }
    }
    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          conn.end();
          return reject(err);
        }
        stream.on("close", (code) => {
          clearTimeout(timer);
          conn.end();
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
    }).on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`SSH connection error: ${err.message}`));
    }).connect({
      host: server.host,
      port: server.port || 22,
      username: server.username,
      privateKey,
      readyTimeout: 15e3,
      keepaliveInterval: 1e4,
      // FIPS 140-3: Restrict to NIST-approved SSH algorithms only
      algorithms: FIPS_SSH_ALGORITHMS
    });
  });
}
function buildEnumCommandStr(config) {
  const amass = config.amassPath || "amass";
  const args = ["enum"];
  switch (config.mode) {
    case "passive":
      args.push("-passive");
      break;
    case "active":
      args.push("-active");
      break;
    case "brute":
      args.push("-brute");
      break;
    case "full":
      args.push("-active", "-brute");
      break;
  }
  for (const domain of config.domains) {
    args.push("-d", sanitize(domain));
  }
  if ((config.mode === "brute" || config.mode === "full") && config.wordlistPath) {
    args.push("-w", config.wordlistPath);
  }
  if (config.ports && config.ports.length > 0) {
    args.push("-p", config.ports.join(","));
  }
  if (config.resolvers && config.resolvers.length > 0) {
    args.push("-r", config.resolvers.join(","));
  }
  if (config.resolverFilePath) {
    args.push("-rf", config.resolverFilePath);
  }
  if (config.blacklist && config.blacklist.length > 0) {
    for (const bl of config.blacklist) {
      args.push("-bl", sanitize(bl));
    }
  }
  if (config.noAlts) args.push("-noalts");
  if (config.noRecursive) args.push("-norecursive");
  if (config.minForRecursive !== void 0) {
    args.push("-min-for-recursive", String(config.minForRecursive));
  }
  if (config.includeUnresolvable) args.push("-include-unresolvable");
  if (config.showSources) args.push("-src");
  if (config.configPath) args.push("-config", config.configPath);
  const timeout = config.timeoutMinutes || 30;
  args.push("-timeout", String(timeout));
  const tmpFile = `/tmp/amass-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.json`;
  args.push("-json", tmpFile);
  const displayCommand = `${amass} ${args.join(" ")}`;
  const command = `${displayCommand} 2>/tmp/amass-stderr.txt; cat ${tmpFile} 2>/dev/null; rm -f ${tmpFile}; cat /tmp/amass-stderr.txt >&2; rm -f /tmp/amass-stderr.txt`;
  return { command, displayCommand };
}
function buildIntelCommand(config) {
  const amass = config.amassPath || "amass";
  const args = ["intel"];
  switch (config.intelMode) {
    case "org":
      args.push("-org", `"${sanitize(config.query)}"`);
      break;
    case "asn":
      args.push("-asn", sanitize(config.query));
      break;
    case "cidr":
      args.push("-cidr", sanitize(config.query));
      break;
    case "whois":
      args.push("-whois", "-d", sanitize(config.query));
      break;
  }
  const displayCommand = `${amass} ${args.join(" ")}`;
  return { command: `${displayCommand} 2>/dev/null`, displayCommand };
}
function sanitize(input) {
  return input.replace(/[;&|`$(){}'"\\]/g, "");
}
function parseAmassJsonOutput(jsonOutput) {
  const subdomains = [];
  const seen = /* @__PURE__ */ new Set();
  const lines = jsonOutput.split("\n").filter((l) => l.trim());
  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (!entry.name) continue;
      const key = entry.name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const subdomain = {
        name: entry.name,
        domain: entry.domain || extractParentDomain(entry.name),
        addresses: (entry.addresses || []).map((addr) => ({
          ip: addr.ip || "",
          cidr: addr.cidr || "",
          asn: addr.asn || 0,
          desc: addr.desc || ""
        })),
        tag: entry.tag || "unknown",
        sources: Array.isArray(entry.sources) ? entry.sources : entry.source ? [entry.source] : []
      };
      subdomains.push(subdomain);
    } catch {
      continue;
    }
  }
  return subdomains;
}
function extractParentDomain(fqdn) {
  const parts = fqdn.split(".");
  if (parts.length <= 2) return fqdn;
  return parts.slice(-2).join(".");
}
function generateAmassSummary(subdomains) {
  const byTag = {};
  const bySource = {};
  const byAsn = {};
  const byDomain = {};
  const allIps = /* @__PURE__ */ new Set();
  const allAsns = /* @__PURE__ */ new Set();
  let resolvedCount = 0;
  let unresolvedCount = 0;
  for (const sub of subdomains) {
    byTag[sub.tag] = (byTag[sub.tag] || 0) + 1;
    for (const src of sub.sources) {
      bySource[src] = (bySource[src] || 0) + 1;
    }
    byDomain[sub.domain] = (byDomain[sub.domain] || 0) + 1;
    if (sub.addresses.length > 0) {
      resolvedCount++;
      for (const addr of sub.addresses) {
        if (addr.ip) allIps.add(addr.ip);
        if (addr.asn) {
          allAsns.add(addr.asn);
          const asnKey = String(addr.asn);
          if (!byAsn[asnKey]) {
            byAsn[asnKey] = { count: 0, desc: addr.desc };
          }
          byAsn[asnKey].count++;
        }
      }
    } else {
      unresolvedCount++;
    }
  }
  return {
    totalSubdomains: subdomains.length,
    totalUniqueIps: allIps.size,
    totalAsns: allAsns.size,
    totalSources: Object.keys(bySource).length,
    resolvedCount,
    unresolvedCount,
    byTag,
    bySource,
    byAsn,
    byDomain
  };
}
async function executeAmassEnum(config) {
  const scanId = `amass-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const startedAt = Date.now();
  const sshTimeout = (config.sshTimeoutSeconds || 2400) * 1e3;
  if (config.engagementId) {
    for (const domain of config.domains) {
      await enforceScope({
        engagementId: config.engagementId,
        targets: [domain],
        toolName: `amass_${config.mode}`,
        action: `Amass ${config.mode} enumeration`
      });
    }
  }
  const { command, displayCommand } = buildEnumCommandStr(config);
  try {
    const { stdout, stderr, exitCode } = await executeSSHCommand(
      config.server,
      command,
      sshTimeout
    );
    const completedAt = Date.now();
    const subdomains = parseAmassJsonOutput(stdout);
    const summary = generateAmassSummary(subdomains);
    const uniqueIps = [...new Set(subdomains.flatMap((s) => s.addresses.map((a) => a.ip)).filter(Boolean))];
    const uniqueAsns = [...new Set(subdomains.flatMap((s) => s.addresses.map((a) => a.asn)).filter(Boolean))];
    const dataSources = [...new Set(subdomains.flatMap((s) => s.sources))];
    return {
      scanId,
      status: exitCode === 0 || subdomains.length > 0 ? "completed" : "failed",
      mode: config.mode,
      domains: config.domains,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      command: displayCommand,
      subdomains,
      uniqueIps,
      uniqueAsns,
      dataSources,
      summary,
      stderr: stderr || void 0,
      error: exitCode !== 0 && subdomains.length === 0 ? `Amass exited with code ${exitCode}` : void 0
    };
  } catch (err) {
    const completedAt = Date.now();
    return {
      scanId,
      status: err.message?.includes("timed out") ? "timeout" : "failed",
      mode: config.mode,
      domains: config.domains,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      command: displayCommand,
      subdomains: [],
      uniqueIps: [],
      uniqueAsns: [],
      dataSources: [],
      summary: {
        totalSubdomains: 0,
        totalUniqueIps: 0,
        totalAsns: 0,
        totalSources: 0,
        resolvedCount: 0,
        unresolvedCount: 0,
        byTag: {},
        bySource: {},
        byAsn: {},
        byDomain: {}
      },
      error: err.message
    };
  }
}
async function executeAmassIntel(config) {
  const scanId = `amass-intel-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const sshTimeout = (config.sshTimeoutSeconds || 120) * 1e3;
  const { command, displayCommand } = buildIntelCommand(config);
  try {
    const { stdout, exitCode } = await executeSSHCommand(
      config.server,
      command,
      sshTimeout
    );
    const discoveries = stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("{"));
    return {
      scanId,
      status: exitCode === 0 ? "completed" : "failed",
      intelMode: config.intelMode,
      query: config.query,
      discoveries,
      error: exitCode !== 0 ? `Amass intel exited with code ${exitCode}` : void 0
    };
  } catch (err) {
    return {
      scanId,
      status: "failed",
      intelMode: config.intelMode,
      query: config.query,
      discoveries: [],
      error: err.message
    };
  }
}
async function scanWithScopeEnforcement(config) {
  const result = await executeAmassEnum(config);
  if (config.engagementId && result.subdomains.length > 0) {
    const filteredSubdomains = [];
    for (const sub of result.subdomains) {
      if (sub.addresses.length === 0) {
        filteredSubdomains.push(sub);
        continue;
      }
      filteredSubdomains.push({
        ...sub,
        addresses: sub.addresses.map((addr) => ({
          ...addr
          // Add a marker for out-of-scope IPs (the UI can highlight these)
        }))
      });
    }
    result.subdomains = filteredSubdomains;
    result.summary = generateAmassSummary(filteredSubdomains);
  }
  return result;
}
async function preflightCheck(server) {
  try {
    const amassPath = "amass";
    const { stdout, exitCode } = await executeSSHCommand(
      server,
      `${amassPath} -version 2>&1 || ${amassPath} --version 2>&1 || echo "amass not found"`,
      1e4
    );
    if (exitCode !== 0 || stdout.includes("not found") || stdout.includes("command not found")) {
      return { available: false, error: "Amass is not installed or not in PATH" };
    }
    const versionMatch = stdout.match(/v?(\d+\.\d+\.\d+)/);
    return {
      available: true,
      version: versionMatch ? versionMatch[1] : stdout.trim().substring(0, 50)
    };
  } catch (err) {
    return { available: false, error: err.message };
  }
}
function toUnifiedDiscoveryFormat(result) {
  return result.subdomains.map((sub) => ({
    type: "subdomain",
    name: sub.name,
    domain: sub.domain,
    ips: sub.addresses.map((a) => a.ip).filter(Boolean),
    asns: sub.addresses.map((a) => a.asn).filter(Boolean),
    sources: sub.sources,
    tag: sub.tag,
    discoveredAt: result.completedAt,
    tool: "amass",
    mode: result.mode
  }));
}
async function deployBuiltInWordlist(server) {
  const wordlistPath = "/tmp/amass-builtin-wordlist.txt";
  const wordlistContent = BUILT_IN_WORDLIST.join("\\n");
  await executeSSHCommand(
    server,
    `echo -e "${wordlistContent}" > ${wordlistPath}`,
    1e4
  );
  return wordlistPath;
}
function diffAmassResults(previous, current) {
  const prevMap = new Map(previous.subdomains.map((s) => [s.name.toLowerCase(), s]));
  const currMap = new Map(current.subdomains.map((s) => [s.name.toLowerCase(), s]));
  const newSubdomains = [];
  const removedSubdomains = [];
  const changedSubdomains = [];
  let unchanged = 0;
  for (const [name, curr] of currMap) {
    const prev = prevMap.get(name);
    if (!prev) {
      newSubdomains.push(curr);
    } else {
      const prevIps = prev.addresses.map((a) => a.ip).sort().join(",");
      const currIps = curr.addresses.map((a) => a.ip).sort().join(",");
      if (prevIps !== currIps) {
        changedSubdomains.push({
          name: curr.name,
          previousIps: prev.addresses.map((a) => a.ip),
          currentIps: curr.addresses.map((a) => a.ip)
        });
      } else {
        unchanged++;
      }
    }
  }
  for (const [name, prev] of prevMap) {
    if (!currMap.has(name)) {
      removedSubdomains.push(prev);
    }
  }
  return {
    newSubdomains,
    removedSubdomains,
    changedSubdomains,
    summary: {
      added: newSubdomains.length,
      removed: removedSubdomains.length,
      changed: changedSubdomains.length,
      unchanged
    }
  };
}

export {
  BUILT_IN_WORDLIST,
  parseAmassJsonOutput,
  generateAmassSummary,
  executeAmassEnum,
  executeAmassIntel,
  scanWithScopeEnforcement,
  preflightCheck,
  toUnifiedDiscoveryFormat,
  deployBuiltInWordlist,
  diffAmassResults
};
