import {
  FIPS_SSH_ALGORITHMS,
  init_fips_ssh
} from "./chunk-SD56WPOS.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanforge-discovery.ts
import { Client as SSHClient } from "ssh2";
import * as fs from "fs";
import * as crypto from "crypto";
function autoSelectTool(config) {
  const { targets, stealthLevel, profile } = config;
  if (profile === "udp") return "naabu";
  if (profile === "full-pipeline") return "naabu";
  if (stealthLevel === "high" || stealthLevel === "maximum") return "naabu";
  if (targets.length === 1 && !targets[0].includes("/")) return "rustscan";
  if (targets.length === 1 && targets[0].includes("/")) {
    const cidr = parseInt(targets[0].split("/")[1], 10);
    if (cidr >= 24) return "naabu";
    if (cidr >= 16) return "masscan";
    return "masscan";
  }
  if (targets.length > 5) return "masscan";
  return "naabu";
}
function buildMasscanArgs(config) {
  const ports = config.ports || "1-1024,3306,3389,5432,5900,6379,8080,8443,27017";
  const rate = config.rate || 1e3;
  const args = [`-p${ports}`, `--rate`, `${rate}`, `-oJ`, `-`];
  if (config.stealthLevel === "high" || config.stealthLevel === "maximum") {
    args.push("--source-port", "53", "--randomize-hosts");
  }
  if (config.excludeHosts?.length) {
    args.push("--excludefile", "/dev/stdin");
  }
  return args;
}
function buildNaabuArgs(config) {
  const args = [];
  if (config.ports) {
    args.push("-p", config.ports);
  } else if (config.profile === "deep" || config.profile === "service") {
    args.push("-p", "-");
  } else {
    args.push("-tp", "1000");
  }
  const rate = config.rate || 500;
  args.push("-rate", `${rate}`);
  args.push("-s", "s");
  args.push("-no-stdin");
  args.push("-Pn");
  args.push("-retries", "1");
  args.push("-json");
  if (config.excludeHosts?.length) {
    args.push("-exclude-hosts", config.excludeHosts.join(","));
  }
  return args;
}
function buildRustScanArgs(config) {
  const args = [];
  if (config.ports) {
    args.push("--range", config.ports);
  } else {
    args.push("--range", "1-65535");
  }
  let batchSize = 4500;
  switch (config.stealthLevel) {
    case "maximum":
      batchSize = 64;
      break;
    case "high":
      batchSize = 128;
      break;
    case "medium":
      batchSize = 500;
      break;
    case "low":
      batchSize = 1e3;
      break;
    case "minimal":
      batchSize = 4500;
      break;
  }
  args.push("-b", `${batchSize}`);
  const timeout = config.stealthLevel === "maximum" || config.stealthLevel === "high" ? 5e3 : 2e3;
  args.push("-t", `${timeout}`);
  args.push("-g");
  return args;
}
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
      algorithms: FIPS_SSH_ALGORITHMS
    });
  });
}
function parseMasscanOutput(output) {
  const hostMap = /* @__PURE__ */ new Map();
  try {
    const cleaned = output.trim().replace(/,\s*\]/, "]").replace(/,\s*$/, "");
    let records;
    try {
      records = JSON.parse(cleaned.startsWith("[") ? cleaned : `[${cleaned}]`);
    } catch {
      records = cleaned.split("\n").filter((line) => line.trim().startsWith("{")).map((line) => {
        try {
          return JSON.parse(line.replace(/,$/, ""));
        } catch {
          return null;
        }
      }).filter(Boolean);
    }
    for (const record of records) {
      if (!record.ip) continue;
      if (!hostMap.has(record.ip)) {
        hostMap.set(record.ip, {
          ip: record.ip,
          hostnames: [],
          status: "up",
          ports: [],
          discoveredBy: "masscan"
        });
      }
      const host = hostMap.get(record.ip);
      if (record.ports && Array.isArray(record.ports)) {
        for (const p of record.ports) {
          host.ports.push({
            port: p.port,
            protocol: p.proto || "tcp",
            state: p.status || "open",
            service: p.service?.name || "unknown",
            banner: p.service?.banner
          });
        }
      }
    }
  } catch (err) {
    const lines = output.split("\n");
    for (const line of lines) {
      const match = line.match(/Discovered open port (\d+)\/(tcp|udp) on ([\d.]+)/);
      if (match) {
        const [, portStr, proto, ip] = match;
        if (!hostMap.has(ip)) {
          hostMap.set(ip, {
            ip,
            hostnames: [],
            status: "up",
            ports: [],
            discoveredBy: "masscan"
          });
        }
        hostMap.get(ip).ports.push({
          port: parseInt(portStr, 10),
          protocol: proto,
          state: "open",
          service: "unknown"
        });
      }
    }
  }
  return Array.from(hostMap.values());
}
function parseNaabuOutput(output) {
  const hostMap = /* @__PURE__ */ new Map();
  const lines = output.split("\n").filter((line) => line.trim().startsWith("{"));
  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      const ip = record.ip || record.host;
      if (!ip) continue;
      if (ip.includes(":") && !ip.startsWith("[")) continue;
      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: record.host && record.host !== ip ? [record.host] : [],
          status: "up",
          ports: [],
          discoveredBy: "naabu"
        });
      }
      const host = hostMap.get(ip);
      if (record.port) {
        host.ports.push({
          port: record.port,
          protocol: record.protocol || "tcp",
          state: "open",
          service: "unknown"
        });
      }
    } catch {
    }
  }
  return Array.from(hostMap.values());
}
function parseRustScanOutput(output) {
  const hostMap = /* @__PURE__ */ new Map();
  const lines = output.split("\n");
  for (const line of lines) {
    const match = line.match(/([\d.]+)\s*->\s*\[([^\]]+)\]/);
    if (match) {
      const [, ip, portsStr] = match;
      const ports = portsStr.split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => !isNaN(p));
      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: [],
          status: "up",
          ports: [],
          discoveredBy: "rustscan"
        });
      }
      const host = hostMap.get(ip);
      for (const port of ports) {
        host.ports.push({
          port,
          protocol: "tcp",
          state: "open",
          service: "unknown"
        });
      }
    }
  }
  return Array.from(hostMap.values());
}
function parseZmapOutput(output) {
  const hostMap = /* @__PURE__ */ new Map();
  const lines = output.split("\n").filter((line) => line.trim().startsWith("{"));
  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      const ip = record.saddr;
      if (!ip) continue;
      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: [],
          status: "up",
          ports: [],
          discoveredBy: "zmap"
        });
      }
      const host = hostMap.get(ip);
      if (record.sport) {
        host.ports.push({
          port: record.sport,
          protocol: "tcp",
          state: "open",
          service: "unknown"
        });
      }
    } catch {
    }
  }
  return Array.from(hostMap.values());
}
function parseHttpxOutput(output) {
  const results = [];
  const lines = output.split("\n").filter((line) => line.trim().startsWith("{"));
  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      results.push({
        url: record.url || record.input,
        host: record.host || "",
        port: record.port || (record.url?.includes(":443") ? 443 : 80),
        statusCode: record["status-code"] || record.status_code || 0,
        title: record.title || "",
        server: record.webserver || record.server,
        technologies: record.tech || record.technologies,
        contentLength: record["content-length"] || record.content_length,
        contentType: record["content-type"] || record.content_type,
        cdn: record.cdn_name || record.cdn
      });
    } catch {
    }
  }
  return results;
}
function parseNucleiOutput(output) {
  const results = [];
  const lines = output.split("\n").filter((line) => line.trim().startsWith("{"));
  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      results.push({
        templateId: record["template-id"] || record.templateID || "",
        name: record.info?.name || record.name || "",
        severity: record.info?.severity || record.severity || "info",
        host: record.host || "",
        matchedAt: record["matched-at"] || record.matched || "",
        description: record.info?.description,
        reference: record.info?.reference,
        tags: record.info?.tags ? typeof record.info.tags === "string" ? record.info.tags.split(",") : record.info.tags : void 0,
        cve: record.info?.classification?.["cve-id"]?.[0]
      });
    } catch {
    }
  }
  return results;
}
async function executeScanforgeScan(config) {
  const scanId = `sf-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const startedAt = Date.now();
  const timeoutMs = (config.timeoutSeconds || 600) * 1e3;
  const profileConfig = PROFILE_CONFIGS[config.profile](config);
  const tool = config.tool || profileConfig.tool;
  const args = config.profile === "custom" && config.customArgs ? config.customArgs.split(/\s+/) : profileConfig.args;
  const safeTargets = config.targets.map((t) => t.replace(/[;&|`$(){}]/g, ""));
  let command;
  switch (tool) {
    case "masscan":
      command = `sudo masscan ${safeTargets.join(" ")} ${args.join(" ")} 2>/dev/null`;
      break;
    case "naabu":
      command = `rm -f /root/.config/naabu/resume.cfg && sudo naabu -host ${safeTargets.join(",")} ${args.join(" ")} 2>/dev/null`;
      break;
    case "rustscan":
      command = `rustscan -a ${safeTargets.join(",")} ${args.join(" ")} 2>/dev/null`;
      break;
    case "zmap":
      command = `sudo zmap ${safeTargets.join(" ")} ${args.join(" ")} 2>/dev/null`;
      break;
    default:
      command = `naabu -host ${safeTargets.join(",")} ${args.join(" ")} 2>/dev/null`;
  }
  if (config.chainHttpx) {
    const httpxRate = config.stealthLevel === "high" || config.stealthLevel === "maximum" ? "-rate-limit 10" : "";
    if (tool === "naabu") {
      command = command.replace("-json", "-silent");
      command += ` | httpx -json -title -tech-detect -status-code -server -follow-redirects ${httpxRate}`;
    }
  }
  if (config.chainNuclei && config.chainHttpx) {
    const nucleiRate = config.stealthLevel === "high" || config.stealthLevel === "maximum" ? "-rate-limit 10" : "";
    const tags = config.nucleiTags?.length ? `-tags ${config.nucleiTags.join(",")}` : "-tags cve,misconfig";
    const severity = config.nucleiSeverity?.length ? `-severity ${config.nucleiSeverity.join(",")}` : "-severity medium,high,critical";
    command += ` | nuclei -json ${tags} ${severity} ${nucleiRate}`;
  }
  try {
    const { stdout, stderr, exitCode } = await executeSSHCommand(config.server, command, timeoutMs);
    if (exitCode !== 0 && !stdout.trim()) {
      return {
        scanId,
        status: "failed",
        tool,
        startedAt,
        completedAt: Date.now(),
        durationMs: Date.now() - startedAt,
        command,
        hosts: [],
        summary: emptySummary(tool, config.profile),
        error: stderr || `${tool} exited with code ${exitCode}`
      };
    }
    let hosts;
    let httpxResults;
    let nucleiResults;
    if (config.chainHttpx && !config.chainNuclei) {
      httpxResults = parseHttpxOutput(stdout);
      hosts = httpxResultsToHosts(httpxResults, tool);
    } else if (config.chainNuclei) {
      nucleiResults = parseNucleiOutput(stdout);
      hosts = nucleiResultsToHosts(nucleiResults, tool);
    } else {
      const parser = OUTPUT_PARSERS[tool];
      hosts = parser(stdout);
    }
    const allPorts = hosts.flatMap((h) => h.ports);
    const summary = {
      totalHosts: hosts.length,
      hostsUp: hosts.filter((h) => h.status === "up").length,
      totalPorts: allPorts.length,
      openPorts: allPorts.filter((p) => p.state === "open").length,
      filteredPorts: allPorts.filter((p) => p.state === "filtered" || p.state === "open|filtered").length,
      uniqueServices: [...new Set(allPorts.map((p) => p.service).filter((s) => s !== "unknown"))],
      uniqueProducts: [...new Set(allPorts.map((p) => p.product).filter((p) => !!p))],
      tool,
      profile: config.profile
    };
    if (httpxResults) {
      summary.webServicesFound = httpxResults.length;
      summary.technologiesDetected = [...new Set(httpxResults.flatMap((r) => r.technologies || []))];
    }
    if (nucleiResults) {
      summary.vulnsFound = nucleiResults.length;
      summary.criticalVulns = nucleiResults.filter((r) => r.severity === "critical").length;
      summary.highVulns = nucleiResults.filter((r) => r.severity === "high").length;
    }
    return {
      scanId,
      status: "completed",
      tool,
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command,
      hosts,
      summary,
      httpxResults,
      nucleiResults,
      rawOutput: stdout.length < 5e6 ? stdout : void 0
    };
  } catch (err) {
    return {
      scanId,
      status: err.message.includes("timed out") ? "timeout" : "failed",
      tool,
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command,
      hosts: [],
      summary: emptySummary(tool, config.profile),
      error: err.message
    };
  }
}
function httpxResultsToHosts(results, tool) {
  const hostMap = /* @__PURE__ */ new Map();
  for (const r of results) {
    const ip = r.host || new URL(r.url).hostname;
    if (!hostMap.has(ip)) {
      hostMap.set(ip, {
        ip,
        hostnames: [],
        status: "up",
        ports: [],
        discoveredBy: tool
      });
    }
    const host = hostMap.get(ip);
    host.ports.push({
      port: r.port,
      protocol: "tcp",
      state: "open",
      service: r.port === 443 ? "https" : "http",
      product: r.server,
      banner: r.title
    });
  }
  return Array.from(hostMap.values());
}
function nucleiResultsToHosts(results, tool) {
  const hostMap = /* @__PURE__ */ new Map();
  for (const r of results) {
    const ip = r.host;
    if (!ip) continue;
    if (!hostMap.has(ip)) {
      hostMap.set(ip, {
        ip,
        hostnames: [],
        status: "up",
        ports: [],
        discoveredBy: tool
      });
    }
  }
  return Array.from(hostMap.values());
}
function emptySummary(tool, profile) {
  return {
    totalHosts: 0,
    hostsUp: 0,
    totalPorts: 0,
    openPorts: 0,
    filteredPorts: 0,
    uniqueServices: [],
    uniqueProducts: [],
    tool,
    profile
  };
}
function toScanforgeRawResults(scanResult, policyProfile) {
  return scanResult.hosts.map((host) => ({
    host: host.ip,
    ports: host.ports.map((p) => ({
      port: p.port,
      protocol: p.protocol,
      service: p.service || null,
      version: p.version ? `${p.product || ""} ${p.version}`.trim() : p.product || null,
      banner: p.banner || null,
      serviceConfidence: p.serviceConf || 0.5,
      scripts: []
      // ScanForge tools don't have NSE-style scripts
    })),
    os: null,
    // ScanForge discovery tools don't do OS detection
    tags: [
      `tool:${scanResult.tool}`,
      `profile:${scanResult.summary.profile}`
    ],
    // Keep field name as serviceVersion for backward compatibility with SSIL adapter
    serviceVersion: `scanforge:${scanResult.tool}`,
    scanRunId: scanResult.scanId,
    policyProfile: policyProfile || "active-standard"
  }));
}
async function scanWithScopeEnforcement(config) {
  const { enforceScope } = await import("./scope-guard-WMDDBR4G.js");
  await enforceScope({
    engagementId: config.engagementId,
    targets: config.targets.map((t) => ({ value: t })),
    tool: `scanforge:${config.tool || autoSelectTool(config)}:${config.profile}`,
    operatorId: config.operatorId,
    operatorName: config.operatorName
  });
  return executeScanforgeScan(config);
}
async function preflightCheck(server) {
  const tools = {};
  try {
    const checks = [
      { name: "masscan", cmd: "masscan --version 2>&1 | head -1" },
      { name: "naabu", cmd: "naabu -version 2>&1 | head -1" },
      { name: "rustscan", cmd: "rustscan --version 2>&1 | head -1" },
      { name: "zmap", cmd: "zmap --version 2>&1 | head -1" },
      { name: "httpx", cmd: "httpx -version 2>&1 | head -1" },
      { name: "nuclei", cmd: "nuclei -version 2>&1 | head -1" }
    ];
    for (const check of checks) {
      try {
        const { stdout, exitCode } = await executeSSHCommand(server, check.cmd, 1e4);
        const version = stdout.trim().match(/[\d.]+/)?.[0];
        tools[check.name] = {
          installed: exitCode === 0 || stdout.includes(check.name) || !!version,
          version: version || "unknown"
        };
      } catch {
        tools[check.name] = { installed: false };
      }
    }
    let hasSudo = false;
    try {
      const sudoResult = await executeSSHCommand(server, "sudo -n true 2>&1", 5e3);
      hasSudo = sudoResult.exitCode === 0;
    } catch {
      hasSudo = false;
    }
    const anyInstalled = Object.values(tools).some((t) => t.installed);
    return {
      available: anyInstalled,
      tools,
      hasSudo
    };
  } catch (err) {
    return {
      available: false,
      tools,
      error: err.message
    };
  }
}
var PROFILE_CONFIGS, OUTPUT_PARSERS;
var init_scanforge_discovery = __esm({
  "server/lib/scanforge-discovery.ts"() {
    init_fips_ssh();
    PROFILE_CONFIGS = {
      quick: (config) => ({
        tool: config.tool || autoSelectTool(config),
        args: config.tool === "masscan" ? buildMasscanArgs({ ...config, ports: config.ports || "1-1024", rate: config.rate || 5e3 }) : config.tool === "rustscan" ? buildRustScanArgs({ ...config, ports: "1-1024" }) : buildNaabuArgs({ ...config, ports: void 0 })
        // top-ports 1000 default
      }),
      standard: (config) => ({
        tool: config.tool || autoSelectTool(config),
        args: config.tool === "masscan" ? buildMasscanArgs(config) : config.tool === "rustscan" ? buildRustScanArgs(config) : buildNaabuArgs(config)
      }),
      deep: (config) => ({
        tool: config.tool || "masscan",
        args: config.tool === "masscan" ? buildMasscanArgs({ ...config, ports: "0-65535", rate: config.rate || 5e3 }) : config.tool === "rustscan" ? buildRustScanArgs({ ...config, ports: "1-65535" }) : buildNaabuArgs({ ...config, ports: "-" })
      }),
      stealth: (config) => ({
        tool: "naabu",
        args: buildNaabuArgs({ ...config, rate: config.rate || 50, stealthLevel: "high" })
      }),
      service: (config) => ({
        tool: config.tool || "naabu",
        args: buildNaabuArgs({ ...config, ports: config.ports || "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017" })
      }),
      udp: (config) => ({
        tool: "naabu",
        args: buildNaabuArgs({ ...config, profile: "udp" })
      }),
      "full-pipeline": (config) => ({
        tool: config.tool || "naabu",
        args: buildNaabuArgs(config)
      }),
      custom: (config) => ({
        tool: config.tool || "naabu",
        args: config.customArgs ? config.customArgs.split(/\s+/) : buildNaabuArgs(config)
      })
    };
    OUTPUT_PARSERS = {
      masscan: parseMasscanOutput,
      naabu: parseNaabuOutput,
      rustscan: parseRustScanOutput,
      zmap: parseZmapOutput
    };
  }
});

export {
  autoSelectTool,
  parseMasscanOutput,
  parseNaabuOutput,
  parseRustScanOutput,
  parseZmapOutput,
  parseHttpxOutput,
  parseNucleiOutput,
  executeScanforgeScan,
  toScanforgeRawResults,
  scanWithScopeEnforcement,
  preflightCheck,
  init_scanforge_discovery
};
