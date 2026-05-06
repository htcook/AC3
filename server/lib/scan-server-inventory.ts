/**
 * Scan Server Tool Inventory — SSH-based tool detection and version checking
 *
 * Provides a comprehensive inventory of tools installed on the scan server,
 * including version info, paths, and capability metadata. This data is used by:
 * 1. The LLM scan planner to select available tools for engagement plans
 * 2. The pre-engagement health check to validate tool availability
 * 3. The frontend to display scan server capabilities
 *
 * Architecture:
 *   - Reads /opt/tool-manifest.json for pre-declared tools (fast path)
 *   - Falls back to `which` + `--version` probing for each tool (slow path)
 *   - Caches results for 5 minutes to avoid repeated SSH calls
 *   - Groups tools by category for LLM context injection
 */

import { executeSSHWithRetry } from "./scan-server-executor";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ToolInfo {
  name: string;
  installed: boolean;
  path?: string;
  version?: string;
  category: ToolCategory;
  description: string;
  /** Whether this tool requires sudo to run */
  requiresSudo: boolean;
}

export type ToolCategory =
  | "port_scanning"
  | "web_scanning"
  | "vuln_scanning"
  | "exploitation"
  | "credential_testing"
  | "dns_recon"
  | "web_fuzzing"
  | "ssl_tls"
  | "cloud_enum"
  | "packet_capture"
  | "service_enum"
  | "screenshot"
  | "utility";

export interface ToolInventory {
  /** Timestamp when inventory was last refreshed */
  lastRefreshed: number;
  /** Whether the scan server was reachable */
  serverReachable: boolean;
  /** Error message if server was unreachable */
  error?: string;
  /** All detected tools */
  tools: ToolInfo[];
  /** Server resource info */
  resources?: {
    uptime?: string;
    diskFree?: string;
    memoryFree?: string;
    cpuCores?: number;
  };
}

// ─── Tool Definitions ───────────────────────────────────────────────────────

interface ToolDefinition {
  name: string;
  category: ToolCategory;
  description: string;
  requiresSudo: boolean;
  /** Command to check if installed (defaults to `which <name>`) */
  checkCommand?: string;
  /** Command to get version (defaults to `<name> --version 2>&1 | head -1`) */
  versionCommand?: string;
  /** Alternative binary names to check */
  altNames?: string[];
}

const TOOL_DEFINITIONS: ToolDefinition[] = [
  // Port Scanning
  { name: "nmap", category: "port_scanning", description: "Network mapper — port scanning, service detection, OS fingerprinting", requiresSudo: true },
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
  { name: "tshark", category: "packet_capture", description: "Wireshark CLI — deep packet inspection", requiresSudo: true },

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
  { name: "jq", category: "utility", description: "JSON processor", requiresSudo: false },
];

// ─── Cache ──────────────────────────────────────────────────────────────────

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
let cachedInventory: ToolInventory | null = null;
let cacheTimestamp = 0;

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Get the full tool inventory from the scan server.
 * Uses cache if available and fresh (< 5 min old).
 */
export async function getToolInventory(forceRefresh = false): Promise<ToolInventory> {
  if (!forceRefresh && cachedInventory && Date.now() - cacheTimestamp < CACHE_TTL_MS) {
    return cachedInventory;
  }

  try {
    const inventory = await probeToolInventory();
    cachedInventory = inventory;
    cacheTimestamp = Date.now();
    return inventory;
  } catch (err: any) {
    return {
      lastRefreshed: Date.now(),
      serverReachable: false,
      error: err.message,
      tools: [],
    };
  }
}

/**
 * Get a compact summary suitable for LLM context injection.
 * Groups tools by category and only includes installed tools.
 */
export function getInventoryForLLM(inventory: ToolInventory): string {
  if (!inventory.serverReachable) {
    return `[SCAN SERVER UNREACHABLE] No tools available. Error: ${inventory.error || "Unknown"}`;
  }

  const installed = inventory.tools.filter((t) => t.installed);
  if (installed.length === 0) {
    return "[SCAN SERVER] Connected but no tools detected. Manual tool installation may be required.";
  }

  const byCategory = new Map<ToolCategory, ToolInfo[]>();
  for (const tool of installed) {
    const list = byCategory.get(tool.category) || [];
    list.push(tool);
    byCategory.set(tool.category, list);
  }

  const categoryLabels: Record<ToolCategory, string> = {
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
    utility: "Utility",
  };

  let output = `[SCAN SERVER TOOLS] ${installed.length}/${TOOL_DEFINITIONS.length} tools available:\n`;
  for (const [category, tools] of byCategory) {
    output += `\n${categoryLabels[category]}:\n`;
    for (const t of tools) {
      output += `  - ${t.name}${t.version ? ` (${t.version})` : ""}${t.requiresSudo ? " [sudo]" : ""}: ${t.description}\n`;
    }
  }

  const missing = inventory.tools.filter((t) => !t.installed);
  if (missing.length > 0) {
    output += `\nNOT INSTALLED (${missing.length}): ${missing.map((t) => t.name).join(", ")}`;
    output += `\nDo NOT generate commands for tools that are not installed.`;
  }

  return output;
}

/**
 * Invalidate the cache (e.g., after tool installation).
 */
export function invalidateInventoryCache(): void {
  cachedInventory = null;
  cacheTimestamp = 0;
}

// ─── Internal ───────────────────────────────────────────────────────────────

async function probeToolInventory(): Promise<ToolInventory> {
  // Step 1: Try reading the manifest (fast path)
  let manifestTools: Record<string, { path?: string; version?: string }> = {};
  try {
    const manifestResult = await executeSSHWithRetry(
      "cat /opt/tool-manifest.json 2>/dev/null",
      10,
      true
    );
    if (manifestResult.stdout.trim()) {
      const manifest = JSON.parse(manifestResult.stdout.trim());
      manifestTools = manifest.tools || {};
    }
  } catch {
    // Manifest not available, will probe individually
  }

  // Step 2: Build batch `which` command for all tools
  const allBinaries = new Set<string>();
  for (const def of TOOL_DEFINITIONS) {
    allBinaries.add(def.name);
    if (def.altNames) def.altNames.forEach((n) => allBinaries.add(n));
  }

  // Batch check: run `which` for all tools in one SSH call
  const whichCommands = Array.from(allBinaries)
    .map((bin) => `echo "CHECK:${bin}:$(which ${bin} 2>/dev/null || echo 'NOT_FOUND')"`)
    .join(" && ");

  let whichResults: Record<string, string> = {};
  try {
    const whichOutput = await executeSSHWithRetry(whichCommands, 30, true);
    for (const line of whichOutput.stdout.split("\n")) {
      const match = line.match(/^CHECK:([^:]+):(.+)$/);
      if (match) {
        whichResults[match[1]] = match[2] === "NOT_FOUND" ? "" : match[2];
      }
    }
  } catch {
    // SSH failed entirely
    throw new Error("Failed to probe scan server tools via SSH");
  }

  // Step 3: Get versions for installed tools (batch)
  const installedBins = Object.entries(whichResults)
    .filter(([, path]) => path)
    .map(([name]) => name);

  let versionResults: Record<string, string> = {};
  if (installedBins.length > 0) {
    // Only get versions for a subset to avoid timeout (top priority tools)
    const priorityTools = ["nmap", "nuclei", "httpx", "naabu", "masscan", "ffuf", "msfconsole", "hydra", "sqlmap", "nikto"];
    const toVersion = installedBins.filter((b) => priorityTools.includes(b)).slice(0, 15);

    if (toVersion.length > 0) {
      const versionCommands = toVersion
        .map((bin) => {
          const def = TOOL_DEFINITIONS.find((d) => d.name === bin || d.altNames?.includes(bin));
          const vCmd = def?.versionCommand || `${bin} --version 2>&1 | head -1`;
          return `echo "VER:${bin}:$(${vCmd} 2>/dev/null | head -1 || echo 'unknown')"`;
        })
        .join(" && ");

      try {
        const versionOutput = await executeSSHWithRetry(versionCommands, 30, true);
        for (const line of versionOutput.stdout.split("\n")) {
          const match = line.match(/^VER:([^:]+):(.+)$/);
          if (match && match[2] !== "unknown") {
            // Extract version number from output
            const verMatch = match[2].match(/(\d+\.\d+[\.\d]*)/);
            versionResults[match[1]] = verMatch ? verMatch[1] : match[2].slice(0, 50);
          }
        }
      } catch {
        // Version check failed, continue without versions
      }
    }
  }

  // Step 4: Get server resources
  let resources: ToolInventory["resources"];
  try {
    const resourceOutput = await executeSSHWithRetry(
      "echo \"UPTIME:$(uptime -p 2>/dev/null || uptime)\" && echo \"DISK:$(df -h / | tail -1 | awk '{print $4}')\" && echo \"MEM:$(free -h | grep Mem | awk '{print $7}')\" && echo \"CPU:$(nproc 2>/dev/null || echo 0)\"",
      10,
      true
    );
    const lines = resourceOutput.stdout.split("\n");
    resources = {};
    for (const line of lines) {
      if (line.startsWith("UPTIME:")) resources.uptime = line.slice(7).trim();
      if (line.startsWith("DISK:")) resources.diskFree = line.slice(5).trim();
      if (line.startsWith("MEM:")) resources.memoryFree = line.slice(4).trim();
      if (line.startsWith("CPU:")) resources.cpuCores = parseInt(line.slice(4)) || undefined;
    }
  } catch {
    // Resource check failed
  }

  // Step 5: Build final inventory
  const tools: ToolInfo[] = TOOL_DEFINITIONS.map((def) => {
    // Check manifest first
    const manifestEntry = manifestTools[def.name];
    if (manifestEntry) {
      return {
        name: def.name,
        installed: true,
        path: manifestEntry.path,
        version: manifestEntry.version || versionResults[def.name],
        category: def.category,
        description: def.description,
        requiresSudo: def.requiresSudo,
      };
    }

    // Check `which` results
    const path = whichResults[def.name] || (def.altNames?.find((n) => whichResults[n]) ? whichResults[def.altNames.find((n) => whichResults[n])!] : undefined);
    const installed = !!path;

    return {
      name: def.name,
      installed,
      path: path || undefined,
      version: versionResults[def.name],
      category: def.category,
      description: def.description,
      requiresSudo: def.requiresSudo,
    };
  });

  return {
    lastRefreshed: Date.now(),
    serverReachable: true,
    tools,
    resources,
  };
}
