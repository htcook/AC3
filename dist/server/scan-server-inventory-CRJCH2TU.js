import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-LGE6KOAQ.js";
import "./chunk-U3JZP3FQ.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-SD56WPOS.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-TYPEU32S.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scan-server-inventory.ts
async function execSSH(command, timeoutSec = 30, _ignoreErrors = false) {
  const result = await executeRawCommand(command, timeoutSec);
  return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode, timedOut: result.timedOut };
}
async function getToolInventory(forceRefresh = false) {
  if (!forceRefresh && cachedInventory && Date.now() - cacheTimestamp < CACHE_TTL_MS) {
    return cachedInventory;
  }
  try {
    const inventory = await probeToolInventory();
    cachedInventory = inventory;
    cacheTimestamp = Date.now();
    return inventory;
  } catch (err) {
    return {
      lastRefreshed: Date.now(),
      serverReachable: false,
      error: err.message,
      tools: []
    };
  }
}
function getInventoryForLLM(inventory) {
  if (!inventory.serverReachable) {
    return `[SCAN SERVER UNREACHABLE] No tools available. Error: ${inventory.error || "Unknown"}`;
  }
  const installed = inventory.tools.filter((t) => t.installed);
  if (installed.length === 0) {
    return "[SCAN SERVER] Connected but no tools detected. Manual tool installation may be required.";
  }
  const byCategory = /* @__PURE__ */ new Map();
  for (const tool of installed) {
    const list = byCategory.get(tool.category) || [];
    list.push(tool);
    byCategory.set(tool.category, list);
  }
  const categoryLabels = {
    port_scanning: "Port Scanning",
    web_scanning: "Web Scanning",
    vuln_scanning: "Vulnerability Scanning",
    exploitation: "Exploitation",
    credential_testing: "Credential Testing",
    dns_recon: "DNS Recon",
    web_fuzzing: "Web Fuzzing",
    ssl_tls: "SSL/TLS Testing",
    cloud_enum: "Cloud Enumeration",
    packet_capture: "Packet Capture",
    service_enum: "Service Enumeration",
    screenshot: "Screenshot",
    utility: "Utility"
  };
  let output = `[SCAN SERVER TOOLS] ${installed.length}/${TOOL_DEFINITIONS.length} tools available:
`;
  for (const [category, tools] of byCategory) {
    output += `
${categoryLabels[category]}:
`;
    for (const t of tools) {
      output += `  - ${t.name}${t.version ? ` (${t.version})` : ""}${t.requiresSudo ? " [sudo]" : ""}: ${t.description}
`;
    }
  }
  const missing = inventory.tools.filter((t) => !t.installed);
  if (missing.length > 0) {
    output += `
NOT INSTALLED (${missing.length}): ${missing.map((t) => t.name).join(", ")}`;
    output += `
Do NOT generate commands for tools that are not installed.`;
  }
  return output;
}
function invalidateInventoryCache() {
  cachedInventory = null;
  cacheTimestamp = 0;
}
async function probeToolInventory() {
  let manifestTools = {};
  try {
    const manifestResult = await execSSH(
      "cat /opt/tool-manifest.json 2>/dev/null",
      10,
      true
    );
    if (manifestResult.stdout.trim()) {
      const manifest = JSON.parse(manifestResult.stdout.trim());
      manifestTools = manifest.tools || {};
    }
  } catch {
  }
  const allBinaries = /* @__PURE__ */ new Set();
  for (const def of TOOL_DEFINITIONS) {
    allBinaries.add(def.name);
    if (def.altNames) def.altNames.forEach((n) => allBinaries.add(n));
  }
  const whichCommands = Array.from(allBinaries).map((bin) => `echo "CHECK:${bin}:$(which ${bin} 2>/dev/null || echo 'NOT_FOUND')"`).join(" && ");
  let whichResults = {};
  try {
    const whichOutput = await execSSH(whichCommands, 30, true);
    for (const line of whichOutput.stdout.split("\n")) {
      const match = line.match(/^CHECK:([^:]+):(.+)$/);
      if (match) {
        whichResults[match[1]] = match[2] === "NOT_FOUND" ? "" : match[2];
      }
    }
  } catch {
    throw new Error("Failed to probe scan server tools via SSH");
  }
  const installedBins = Object.entries(whichResults).filter(([, path]) => path).map(([name]) => name);
  let versionResults = {};
  if (installedBins.length > 0) {
    const priorityTools = ["nmap", "nuclei", "httpx", "naabu", "masscan", "ffuf", "msfconsole", "hydra", "sqlmap", "nikto"];
    const toVersion = installedBins.filter((b) => priorityTools.includes(b)).slice(0, 15);
    if (toVersion.length > 0) {
      const versionCommands = toVersion.map((bin) => {
        const def = TOOL_DEFINITIONS.find((d) => d.name === bin || d.altNames?.includes(bin));
        const vCmd = def?.versionCommand || `${bin} --version 2>&1 | head -1`;
        return `echo "VER:${bin}:$(${vCmd} 2>/dev/null | head -1 || echo 'unknown')"`;
      }).join(" && ");
      try {
        const versionOutput = await execSSH(versionCommands, 30, true);
        for (const line of versionOutput.stdout.split("\n")) {
          const match = line.match(/^VER:([^:]+):(.+)$/);
          if (match && match[2] !== "unknown") {
            const verMatch = match[2].match(/(\d+\.\d+[\.\d]*)/);
            versionResults[match[1]] = verMatch ? verMatch[1] : match[2].slice(0, 50);
          }
        }
      } catch {
      }
    }
  }
  let resources;
  try {
    const resourceOutput = await execSSH(
      `echo "UPTIME:$(uptime -p 2>/dev/null || uptime)" && echo "DISK:$(df -h / | tail -1 | awk '{print $4}')" && echo "MEM:$(free -h | grep Mem | awk '{print $7}')" && echo "CPU:$(nproc 2>/dev/null || echo 0)"`,
      10,
      true
    );
    const lines = resourceOutput.stdout.split("\n");
    resources = {};
    for (const line of lines) {
      if (line.startsWith("UPTIME:")) resources.uptime = line.slice(7).trim();
      if (line.startsWith("DISK:")) resources.diskFree = line.slice(5).trim();
      if (line.startsWith("MEM:")) resources.memoryFree = line.slice(4).trim();
      if (line.startsWith("CPU:")) resources.cpuCores = parseInt(line.slice(4)) || void 0;
    }
  } catch {
  }
  const tools = TOOL_DEFINITIONS.map((def) => {
    const manifestEntry = manifestTools[def.name];
    if (manifestEntry) {
      return {
        name: def.name,
        installed: true,
        path: manifestEntry.path,
        version: manifestEntry.version || versionResults[def.name],
        category: def.category,
        description: def.description,
        requiresSudo: def.requiresSudo
      };
    }
    const path = whichResults[def.name] || (def.altNames?.find((n) => whichResults[n]) ? whichResults[def.altNames.find((n) => whichResults[n])] : void 0);
    const installed = !!path;
    return {
      name: def.name,
      installed,
      path: path || void 0,
      version: versionResults[def.name],
      category: def.category,
      description: def.description,
      requiresSudo: def.requiresSudo
    };
  });
  return {
    lastRefreshed: Date.now(),
    serverReachable: true,
    tools,
    resources
  };
}
var TOOL_DEFINITIONS, CACHE_TTL_MS, cachedInventory, cacheTimestamp;
var init_scan_server_inventory = __esm({
  "server/lib/scan-server-inventory.ts"() {
    init_scan_server_executor();
    TOOL_DEFINITIONS = [
      // Port Scanning
      { name: "nmap", category: "port_scanning", description: "Network mapper \u2014 port scanning, service detection, OS fingerprinting", requiresSudo: true },
      { name: "masscan", category: "port_scanning", description: "High-speed port scanner (10M+ pps)", requiresSudo: true },
      { name: "naabu", category: "port_scanning", description: "Fast port scanner with SYN/CONNECT probes", requiresSudo: true },
      { name: "rustscan", category: "port_scanning", description: "Ultra-fast port scanner (Rust-based)", requiresSudo: false },
      { name: "zmap", category: "port_scanning", description: "Internet-wide single-port scanner", requiresSudo: true },
      // Web Scanning
      { name: "nikto", category: "web_scanning", description: "Web server vulnerability scanner", requiresSudo: false, versionCommand: "nikto -Version 2>&1 | head -1" },
      { name: "whatweb", category: "web_scanning", description: "Web technology fingerprinter", requiresSudo: false },
      { name: "wpscan", category: "web_scanning", description: "WordPress vulnerability scanner", requiresSudo: false },
      { name: "katana", category: "web_scanning", description: "Web crawler and content discovery", requiresSudo: false },
      // Vulnerability Scanning
      { name: "nuclei", category: "vuln_scanning", description: "Template-based vulnerability scanner (ProjectDiscovery)", requiresSudo: false },
      { name: "zap-cli", category: "vuln_scanning", description: "OWASP ZAP CLI interface", requiresSudo: false, altNames: ["zap.sh", "zaproxy"] },
      // Exploitation
      { name: "msfconsole", category: "exploitation", description: "Metasploit Framework console", requiresSudo: false, versionCommand: "msfconsole --version 2>&1 | head -1" },
      { name: "sqlmap", category: "exploitation", description: "SQL injection detection and exploitation", requiresSudo: false },
      { name: "commix", category: "exploitation", description: "Command injection exploiter", requiresSudo: false },
      // Credential Testing
      { name: "hydra", category: "credential_testing", description: "Network login cracker (brute-force)", requiresSudo: false },
      { name: "crackmapexec", category: "credential_testing", description: "Network credential testing (SMB/WinRM/SSH/LDAP)", requiresSudo: false, altNames: ["cme", "nxc"] },
      // DNS Recon
      { name: "subfinder", category: "dns_recon", description: "Subdomain discovery tool", requiresSudo: false },
      { name: "dig", category: "dns_recon", description: "DNS lookup utility", requiresSudo: false },
      { name: "whois", category: "dns_recon", description: "Domain registration lookup", requiresSudo: false },
      // Web Fuzzing
      { name: "ffuf", category: "web_fuzzing", description: "Fast web fuzzer (directories, parameters, vhosts)", requiresSudo: false },
      { name: "gobuster", category: "web_fuzzing", description: "Directory/DNS/vhost brute-forcer", requiresSudo: false },
      { name: "feroxbuster", category: "web_fuzzing", description: "Recursive content discovery (Rust-based)", requiresSudo: false },
      { name: "dirb", category: "web_fuzzing", description: "Web content scanner (wordlist-based)", requiresSudo: false },
      { name: "wfuzz", category: "web_fuzzing", description: "Web application fuzzer", requiresSudo: false },
      { name: "arjun", category: "web_fuzzing", description: "HTTP parameter discovery", requiresSudo: false },
      // SSL/TLS
      { name: "testssl.sh", category: "ssl_tls", description: "TLS/SSL cipher and vulnerability tester", requiresSudo: false, checkCommand: "which testssl.sh || which testssl" },
      { name: "sslscan", category: "ssl_tls", description: "SSL/TLS protocol scanner", requiresSudo: false },
      // Cloud Enumeration
      { name: "cloud_enum", category: "cloud_enum", description: "Multi-cloud storage bucket enumeration", requiresSudo: false },
      { name: "s3scanner", category: "cloud_enum", description: "AWS S3 bucket permission scanner", requiresSudo: false },
      { name: "trufflehog", category: "cloud_enum", description: "Secret/credential scanner in repos and cloud", requiresSudo: false },
      // Packet Capture
      { name: "tcpdump", category: "packet_capture", description: "Network packet capture and analysis", requiresSudo: true },
      { name: "tshark", category: "packet_capture", description: "Wireshark CLI \u2014 deep packet inspection", requiresSudo: true },
      // Service Enumeration
      { name: "enum4linux", category: "service_enum", description: "Windows/Samba enumeration", requiresSudo: false },
      { name: "smbclient", category: "service_enum", description: "SMB/CIFS client for share enumeration", requiresSudo: false },
      { name: "ldapsearch", category: "service_enum", description: "LDAP directory enumeration", requiresSudo: false },
      { name: "snmpwalk", category: "service_enum", description: "SNMP tree walker", requiresSudo: false },
      { name: "ssh-audit", category: "service_enum", description: "SSH server configuration auditor", requiresSudo: false },
      { name: "httpx", category: "service_enum", description: "HTTP probe with tech detection", requiresSudo: false },
      // Screenshot
      { name: "chromium", category: "screenshot", description: "Headless browser for screenshots", requiresSudo: false, altNames: ["chromium-browser", "google-chrome"] },
      // Utility
      { name: "docker", category: "utility", description: "Container runtime (for tool isolation)", requiresSudo: false },
      { name: "python3", category: "utility", description: "Python 3 interpreter (for custom scripts)", requiresSudo: false },
      { name: "curl", category: "utility", description: "HTTP client for API calls", requiresSudo: false },
      { name: "jq", category: "utility", description: "JSON processor", requiresSudo: false }
    ];
    CACHE_TTL_MS = 5 * 60 * 1e3;
    cachedInventory = null;
    cacheTimestamp = 0;
  }
});
init_scan_server_inventory();
export {
  getInventoryForLLM,
  getToolInventory,
  invalidateInventoryCache
};
