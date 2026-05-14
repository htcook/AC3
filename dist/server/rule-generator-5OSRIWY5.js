import {
  init_llm,
  invokeLLM
} from "./chunk-TP4TYLYW.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/rule-generator.ts
init_llm();
function generateRuleId() {
  const hex = () => Math.random().toString(16).substring(2, 6);
  return `${hex()}${hex()}-${hex()}-${hex()}-${hex()}-${hex()}${hex()}${hex()}`;
}
function generateSid() {
  return 2e6 + Math.floor(Math.random() * 999999);
}
function todayStr() {
  return (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
}
function getSeverityForTactic(tactic) {
  const m = {
    "reconnaissance": "low",
    "resource-development": "low",
    "initial-access": "high",
    "execution": "high",
    "persistence": "medium",
    "privilege-escalation": "high",
    "defense-evasion": "high",
    "credential-access": "critical",
    "discovery": "medium",
    "lateral-movement": "high",
    "collection": "medium",
    "command-and-control": "high",
    "exfiltration": "critical",
    "impact": "critical"
  };
  return m[tactic] || "medium";
}
function getTacticFromId(techniqueId) {
  const m = {
    "T1595": "reconnaissance",
    "T1592": "reconnaissance",
    "T1566": "initial-access",
    "T1190": "initial-access",
    "T1059": "execution",
    "T1053": "execution",
    "T1078": "persistence",
    "T1547": "persistence",
    "T1068": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1027": "defense-evasion",
    "T1070": "defense-evasion",
    "T1562": "defense-evasion",
    "T1003": "credential-access",
    "T1110": "credential-access",
    "T1555": "credential-access",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1087": "discovery",
    "T1021": "lateral-movement",
    "T1210": "lateral-movement",
    "T1005": "collection",
    "T1074": "collection",
    "T1071": "command-and-control",
    "T1041": "exfiltration",
    "T1567": "exfiltration",
    "T1486": "impact"
  };
  return m[techniqueId] || m[techniqueId.split(".")[0]] || "unknown";
}
var TEMPLATES = {
  "T1059.001": {
    sigma: (t) => `title: ${t.actorName} - PowerShell Execution Pattern
id: ${generateRuleId()}
status: experimental
description: Detects PowerShell execution patterns associated with ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection_process:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_suspicious:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - 'Invoke-Expression'
            - 'IEX('
            - 'DownloadString'
            - 'Net.WebClient'
            - '-WindowStyle Hidden'
            - 'bypass'
            - 'FromBase64String'
    filter_legitimate:
        ParentImage|endswith:
            - '\\\\msiexec.exe'
            - '\\\\sccm\\\\ccmexec.exe'
    condition: selection_process and selection_suspicious and not filter_legitimate
falsepositives:
    - Legitimate administration scripts
    - Software deployment tools
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
    yara: (t) => `rule ${t.actorName.replace(/[^a-zA-Z0-9]/g, "_")}_PowerShell_Payload
{
    meta:
        author = "AC3 / AceofCloud"
        description = "Detects PowerShell payloads associated with ${t.actorName}"
        date = "${todayStr()}"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "high"
        actor = "${t.actorName}"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "FromBase64String" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "Net.WebClient" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX(" ascii wide nocase
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase

    condition:
        $ps1 and (2 of ($enc*, $dl*, $exec*, $bypass))
}`
  },
  "T1059.003": {
    sigma: (t) => `title: ${t.actorName} - Suspicious CMD Execution
id: ${generateRuleId()}
status: experimental
description: Detects suspicious cmd.exe execution patterns used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
        CommandLine|contains:
            - '/c '
            - 'certutil'
            - 'bitsadmin'
            - 'wmic'
            - 'reg add'
            - 'schtasks'
    filter:
        ParentImage|endswith: '\\\\explorer.exe'
    condition: selection and not filter
falsepositives:
    - System administration
level: medium
tags:
    - attack.execution
    - attack.t1059.003`
  },
  "T1566.001": {
    sigma: (t) => `title: ${t.actorName} - Spearphishing Attachment Execution
id: ${generateRuleId()}
status: experimental
description: Detects execution of suspicious files from email attachments by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
references:
    - https://attack.mitre.org/techniques/T1566/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\\\OUTLOOK.EXE'
            - '\\\\WINWORD.EXE'
            - '\\\\EXCEL.EXE'
            - '\\\\POWERPNT.EXE'
    selection_child:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\wscript.exe'
            - '\\\\cscript.exe'
            - '\\\\mshta.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate macros in business documents
level: high
tags:
    - attack.initial-access
    - attack.t1566.001`,
    suricata: (t) => `alert smtp any any -> $HOME_NET any (msg:"${t.actorName} - Suspicious Email Attachment"; flow:established,to_client; file_data; content:".exe"; content:"Content-Disposition"; content:"attachment"; distance:0; sid:${generateSid()}; rev:1; classtype:trojan-activity;)`
  },
  "T1190": {
    sigma: (t) => `title: ${t.actorName} - Web Application Exploitation Indicators
id: ${generateRuleId()}
status: experimental
description: Detects web application exploitation patterns by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: application
detection:
    selection_web:
        EventID:
            - 1000
            - 1001
        Application|contains:
            - 'w3wp.exe'
            - 'httpd.exe'
    selection_cmd:
        CommandLine|contains:
            - 'cmd.exe /c'
            - 'powershell'
            - 'whoami'
            - 'net user'
    condition: selection_web or selection_cmd
falsepositives:
    - Web application debugging
level: high
tags:
    - attack.initial-access
    - attack.t1190`,
    suricata: (t) => `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"${t.actorName} - Web Shell Upload Attempt"; flow:established,to_server; http.method; content:"POST"; http.uri; content:".aspx"; content:"upload"; nocase; sid:${generateSid()}; rev:1; classtype:web-application-attack;)`
  },
  "T1003.001": {
    sigma: (t) => `title: ${t.actorName} - LSASS Memory Credential Dumping
id: ${generateRuleId()}
status: experimental
description: Detects LSASS credential dumping techniques used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1438'
            - '0x143a'
    filter_legitimate:
        SourceImage|endswith:
            - '\\\\MsMpEng.exe'
            - '\\\\csrss.exe'
            - '\\\\wmiprvse.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Security products accessing LSASS
level: critical
tags:
    - attack.credential-access
    - attack.t1003.001`,
    yara: (t) => `rule ${t.actorName.replace(/[^a-zA-Z0-9]/g, "_")}_Credential_Dump_Tool
{
    meta:
        author = "AC3 / AceofCloud"
        description = "Detects credential dumping tools used by ${t.actorName}"
        date = "${todayStr()}"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        severity = "critical"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "lsadump::sam" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "token::elevate" ascii wide nocase
        $s6 = "MiniDumpWriteDump" ascii wide

    condition:
        3 of them
}`
  },
  "T1003.003": {
    sigma: (t) => `title: ${t.actorName} - NTDS.dit Credential Extraction
id: ${generateRuleId()}
status: experimental
description: Detects NTDS.dit extraction for credential harvesting by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection_ntdsutil:
        CommandLine|contains:
            - 'ntdsutil'
            - 'ifm'
            - 'create full'
    selection_vssadmin:
        CommandLine|contains:
            - 'vssadmin'
            - 'create shadow'
    selection_copy:
        CommandLine|contains:
            - 'ntds.dit'
            - 'SYSTEM'
    condition: selection_ntdsutil or (selection_vssadmin and selection_copy)
falsepositives:
    - Legitimate backup operations
level: critical
tags:
    - attack.credential-access
    - attack.t1003.003`
  },
  "T1110": {
    sigma: (t) => `title: ${t.actorName} - Brute Force Authentication Attempts
id: ${generateRuleId()}
status: experimental
description: Detects brute force authentication patterns by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4771
    timeframe: 5m
    condition: selection | count(TargetUserName) by SourceAddress > 10
falsepositives:
    - Password reset operations
level: high
tags:
    - attack.credential-access
    - attack.t1110`
  },
  "T1053": {
    sigma: (t) => `title: ${t.actorName} - Scheduled Task Persistence
id: ${generateRuleId()}
status: experimental
description: Detects scheduled task creation for persistence by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\schtasks.exe'
        CommandLine|contains: '/create'
    selection_suspicious:
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'mshta'
            - 'AppData'
            - 'Temp'
    condition: selection and selection_suspicious
falsepositives:
    - Software installation
level: medium
tags:
    - attack.persistence
    - attack.t1053`
  },
  "T1078": {
    sigma: (t) => `title: ${t.actorName} - Valid Account Abuse (Off-Hours)
id: ${generateRuleId()}
status: experimental
description: Detects suspicious use of valid accounts during off-hours by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType:
            - 3
            - 10
    condition: selection
falsepositives:
    - Legitimate after-hours work
level: medium
tags:
    - attack.persistence
    - attack.t1078`
  },
  "T1027": {
    sigma: (t) => `title: ${t.actorName} - Obfuscated File or Information
id: ${generateRuleId()}
status: experimental
description: Detects obfuscation techniques used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'certutil -decode'
            - 'certutil -urlcache'
            - 'FromBase64String'
            - '-bxor'
    condition: selection
falsepositives:
    - Legitimate encoding operations
level: high
tags:
    - attack.defense-evasion
    - attack.t1027`,
    yara: (t) => `rule ${t.actorName.replace(/[^a-zA-Z0-9]/g, "_")}_Obfuscated_Script
{
    meta:
        author = "AC3 / AceofCloud"
        description = "Detects obfuscated scripts used by ${t.actorName}"
        date = "${todayStr()}"
        severity = "high"

    strings:
        $xor1 = "-bxor" ascii wide nocase
        $chr1 = "[char]" ascii wide nocase
        $concat = "'+'" ascii
        $replace = ".replace(" ascii wide nocase

    condition:
        3 of them and filesize < 500KB
}`
  },
  "T1070.004": {
    sigma: (t) => `title: ${t.actorName} - Indicator Removal on Host
id: ${generateRuleId()}
status: experimental
description: Detects file deletion and log clearing by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'del /f'
            - 'Remove-Item'
            - 'Clear-EventLog'
            - 'wevtutil cl'
    condition: selection
falsepositives:
    - Legitimate cleanup scripts
level: high
tags:
    - attack.defense-evasion
    - attack.t1070.004`
  },
  "T1562.001": {
    sigma: (t) => `title: ${t.actorName} - Security Tool Tampering
id: ${generateRuleId()}
status: experimental
description: Detects attempts to disable security tools by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Set-MpPreference -DisableRealtimeMonitoring'
            - 'sc stop WinDefend'
            - 'sc delete WinDefend'
            - 'net stop'
    condition: selection
falsepositives:
    - Legitimate security tool management
level: critical
tags:
    - attack.defense-evasion
    - attack.t1562.001`
  },
  "T1082": {
    sigma: (t) => `title: ${t.actorName} - System Information Discovery
id: ${generateRuleId()}
status: experimental
description: Detects system enumeration commands used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'systeminfo'
            - 'hostname'
            - 'whoami /all'
            - 'ipconfig /all'
    timeframe: 5m
    condition: selection | count() > 3
falsepositives:
    - System administration
level: medium
tags:
    - attack.discovery
    - attack.t1082`
  },
  "T1087": {
    sigma: (t) => `title: ${t.actorName} - Account Discovery
id: ${generateRuleId()}
status: experimental
description: Detects account enumeration by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'net user'
            - 'net localgroup'
            - 'net group /domain'
            - 'Get-ADUser'
    condition: selection
falsepositives:
    - IT administration
level: medium
tags:
    - attack.discovery
    - attack.t1087`
  },
  "T1021.001": {
    sigma: (t) => `title: ${t.actorName} - RDP Lateral Movement
id: ${generateRuleId()}
status: experimental
description: Detects RDP lateral movement patterns used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    filter_internal:
        SourceNetworkAddress|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
    condition: selection and filter_internal
falsepositives:
    - Legitimate remote administration
level: medium
tags:
    - attack.lateral-movement
    - attack.t1021.001`
  },
  "T1021.002": {
    sigma: (t) => `title: ${t.actorName} - SMB Admin Shares Lateral Movement
id: ${generateRuleId()}
status: experimental
description: Detects SMB lateral movement by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5140
        ShareName|contains:
            - 'ADMIN$'
            - 'C$'
            - 'IPC$'
    condition: selection
falsepositives:
    - Legitimate file sharing
level: medium
tags:
    - attack.lateral-movement
    - attack.t1021.002`
  },
  "T1071.001": {
    sigma: (t) => `title: ${t.actorName} - HTTP C2 Communication Pattern
id: ${generateRuleId()}
status: experimental
description: Detects HTTP-based C2 communication patterns used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - '/api/v1/'
            - '/update/check'
            - '/beacon'
            - '/callback'
    selection_method:
        cs-method: POST
    timeframe: 1h
    condition: selection and selection_method | count() by c-ip > 20
falsepositives:
    - Legitimate API traffic
level: high
tags:
    - attack.command-and-control
    - attack.t1071.001`,
    suricata: (t) => `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"${t.actorName} - Possible C2 Beacon"; flow:established,to_server; http.method; content:"POST"; threshold:type both, track by_src, count 10, seconds 300; sid:${generateSid()}; rev:1; classtype:trojan-activity;)`
  },
  "T1041": {
    sigma: (t) => `title: ${t.actorName} - Data Exfiltration Over C2 Channel
id: ${generateRuleId()}
status: experimental
description: Detects large data transfers over C2 channels by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
        sc-bytes|gte: 1048576
    selection_external:
        r-dns|endswith:
            - '.xyz'
            - '.top'
            - '.tk'
    condition: selection and selection_external
falsepositives:
    - Large file uploads to legitimate services
level: high
tags:
    - attack.exfiltration
    - attack.t1041`
  },
  "T1567": {
    sigma: (t) => `title: ${t.actorName} - Exfiltration to Cloud Storage
id: ${generateRuleId()}
status: experimental
description: Detects data exfiltration to cloud storage services by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
        r-dns|contains:
            - 'mega.nz'
            - 'anonfiles'
            - 'transfer.sh'
            - 'file.io'
    condition: selection
falsepositives:
    - Legitimate cloud storage usage
level: high
tags:
    - attack.exfiltration
    - attack.t1567`
  },
  "T1068": {
    sigma: (t) => `title: ${t.actorName} - Exploitation for Privilege Escalation
id: ${generateRuleId()}
status: experimental
description: Detects privilege escalation exploitation patterns by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        IntegrityLevel: 'High'
        ParentIntegrityLevel: 'Medium'
    selection_suspicious:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
    condition: selection and selection_suspicious
falsepositives:
    - UAC elevation for administration
level: high
tags:
    - attack.privilege-escalation
    - attack.t1068`
  },
  "T1548": {
    sigma: (t) => `title: ${t.actorName} - UAC Bypass Attempt
id: ${generateRuleId()}
status: experimental
description: Detects UAC bypass techniques used by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    category: process_creation
detection:
    selection_child:
        ParentImage|endswith:
            - '\\\\eventvwr.exe'
            - '\\\\fodhelper.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
    condition: selection_child
falsepositives:
    - Legitimate use of these binaries
level: high
tags:
    - attack.privilege-escalation
    - attack.t1548`
  },
  "T1005": {
    sigma: (t) => `title: ${t.actorName} - Sensitive File Access
id: ${generateRuleId()}
status: experimental
description: Detects access to sensitive files by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains:
            - 'password'
            - 'credential'
            - '.kdbx'
            - '.pem'
            - '.key'
    condition: selection
falsepositives:
    - Legitimate file operations
level: medium
tags:
    - attack.collection
    - attack.t1005`
  },
  "T1486": {
    sigma: (t) => `title: ${t.actorName} - Ransomware File Encryption Indicators
id: ${generateRuleId()}
status: experimental
description: Detects ransomware encryption indicators by ${t.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypto'
    timeframe: 1m
    condition: selection | count() > 50
falsepositives:
    - Legitimate encryption software
level: critical
tags:
    - attack.impact
    - attack.t1486`
  },
  "T1595.002": {
    suricata: (t) => `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"${t.actorName} - Active Scanning"; flow:established,to_server; threshold:type both, track by_src, count 100, seconds 60; sid:${generateSid()}; rev:1; classtype:attempted-recon;)`
  }
};
function generateGenericSigmaRule(tech) {
  const tacticTag = tech.tactic.toLowerCase().replace(/\s+/g, "-");
  return `title: ${tech.actorName} - ${tech.name} Detection
id: ${generateRuleId()}
status: experimental
description: Generic detection rule for ${tech.name} (${tech.id}) as used by ${tech.actorName}
author: AC3 / AceofCloud
date: ${todayStr()}
references:
    - https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: '*'
    condition: selection
falsepositives:
    - Requires tuning for environment
level: medium
tags:
    - attack.${tacticTag}
    - attack.${tech.id.toLowerCase()}`;
}
function generateRulesForActor(params) {
  const { actorName, techniques, tools, malware } = params;
  const rules = [];
  let ruleCounter = 0;
  for (const tech of techniques) {
    const techInput = { id: tech.id, name: tech.name, tactic: tech.tactic, actorName, tools, malware };
    const templates = TEMPLATES[tech.id] || TEMPLATES[tech.id.split(".")[0]];
    const tactic = tech.tactic || getTacticFromId(tech.id);
    const severity = getSeverityForTactic(tactic);
    if (templates) {
      if (templates.sigma) {
        ruleCounter++;
        rules.push({
          id: `rule-${ruleCounter}`,
          ruleType: "sigma",
          ruleName: `${actorName} - ${tech.name} (Sigma)`,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tactic,
          ruleContent: templates.sigma(techInput),
          description: `Sigma detection rule for ${tech.name} as used by ${actorName}`,
          severity,
          confidence: 75,
          dataSource: "Windows Event Logs / Sysmon",
          platform: "Windows"
        });
      }
      if (templates.yara) {
        ruleCounter++;
        rules.push({
          id: `rule-${ruleCounter}`,
          ruleType: "yara",
          ruleName: `${actorName} - ${tech.name} (YARA)`,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tactic,
          ruleContent: templates.yara(techInput),
          description: `YARA detection rule for ${tech.name} artifacts from ${actorName}`,
          severity,
          confidence: 70,
          dataSource: "File System / Memory",
          platform: "Cross-platform"
        });
      }
      if (templates.suricata) {
        ruleCounter++;
        rules.push({
          id: `rule-${ruleCounter}`,
          ruleType: "suricata",
          ruleName: `${actorName} - ${tech.name} (Suricata)`,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tactic,
          ruleContent: templates.suricata(techInput),
          description: `Suricata network detection rule for ${tech.name} by ${actorName}`,
          severity,
          confidence: 65,
          dataSource: "Network Traffic",
          platform: "Network"
        });
      }
    } else {
      ruleCounter++;
      rules.push({
        id: `rule-${ruleCounter}`,
        ruleType: "sigma",
        ruleName: `${actorName} - ${tech.name} (Generic Sigma)`,
        techniqueId: tech.id,
        techniqueName: tech.name,
        tactic,
        ruleContent: generateGenericSigmaRule(techInput),
        description: `Generic Sigma detection rule for ${tech.name} - requires environment-specific tuning`,
        severity,
        confidence: 40,
        dataSource: "Windows Event Logs",
        platform: "Windows"
      });
    }
  }
  const rulesByType = {};
  const rulesByTactic = {};
  for (const rule of rules) {
    rulesByType[rule.ruleType] = (rulesByType[rule.ruleType] || 0) + 1;
    rulesByTactic[rule.tactic] = (rulesByTactic[rule.tactic] || 0) + 1;
  }
  return { actorName, totalRules: rules.length, rulesByType, rulesByTactic, rules, generatedAt: (/* @__PURE__ */ new Date()).toISOString() };
}
async function generateRulesWithLLM(params) {
  const baseResult = generateRulesForActor(params);
  const genericRules = baseResult.rules.filter((r) => r.confidence < 50).slice(0, 5);
  if (genericRules.length === 0) return baseResult;
  try {
    const prompt = `You are an expert detection engineer. Generate improved Sigma detection rules for the following techniques used by ${params.actorName}.

ACTOR: ${params.actorName}
DESCRIPTION: ${params.description || "N/A"}
TOOLS: ${(params.tools || []).join(", ") || "N/A"}
MALWARE: ${(params.malware || []).join(", ") || "N/A"}

For each technique below, provide an improved Sigma rule with specific detection logic (not generic wildcards):
${genericRules.map((r) => `- ${r.techniqueId}: ${r.techniqueName} (${r.tactic})`).join("\n")}

Return JSON array of objects with: { techniqueId, sigmaRule }`;
    const response = await invokeLLM({
      _caller: "rule-generator.generateRulesWithLLM",
      messages: [
        { role: "system", content: "You are a detection engineering expert. Return valid JSON only." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "enhanced_rules",
          strict: true,
          schema: {
            type: "object",
            properties: {
              rules: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    techniqueId: { type: "string" },
                    sigmaRule: { type: "string" }
                  },
                  required: ["techniqueId", "sigmaRule"],
                  additionalProperties: false
                }
              }
            },
            required: ["rules"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const enhanced = JSON.parse(content);
    if (enhanced.rules && Array.isArray(enhanced.rules)) {
      for (const er of enhanced.rules) {
        const idx = baseResult.rules.findIndex((r) => r.techniqueId === er.techniqueId && r.confidence < 50);
        if (idx >= 0 && er.sigmaRule) {
          baseResult.rules[idx].ruleContent = er.sigmaRule;
          baseResult.rules[idx].confidence = 70;
          baseResult.rules[idx].description += " (LLM-enhanced)";
        }
      }
    }
  } catch (error) {
    console.error("LLM rule enhancement failed, using template rules:", error);
  }
  return baseResult;
}
export {
  generateRulesForActor,
  generateRulesWithLLM
};
