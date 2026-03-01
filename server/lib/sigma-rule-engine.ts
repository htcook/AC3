/**
 * Sigma Rule Generation Engine
 *
 * Automatically generates Sigma detection rules from ATT&CK techniques,
 * adversary emulation results, and defense validation gaps. Supports
 * template-based generation with optional LLM refinement for context-specific
 * detection logic. Exports to Sigma YAML, Splunk SPL, Microsoft KQL,
 * and Elastic EQL formats.
 *
 * @module sigma-rule-engine
 */

// ─── Types ─────────────────────────────────────────────────────────

export type SigmaLevel = "informational" | "low" | "medium" | "high" | "critical";
export type SigmaStatus = "experimental" | "test" | "stable" | "deprecated";
export type LogSource = "process_creation" | "network_connection" | "file_event" | "registry_event" |
  "image_load" | "dns_query" | "pipe_event" | "wmi_event" | "powershell" | "authentication" |
  "service_creation" | "scheduled_task" | "driver_load" | "cloud_audit" | "firewall";
export type ExportFormat = "sigma" | "splunk_spl" | "kql" | "elastic_eql";

export interface SigmaRule {
  id: string;
  title: string;
  status: SigmaStatus;
  level: SigmaLevel;
  description: string;
  author: string;
  date: string;
  modified: string;
  references: string[];
  tags: string[];
  logsource: {
    category: string;
    product: string;
    service?: string;
  };
  detection: {
    selection: Record<string, string | string[]>;
    condition: string;
    filter?: Record<string, string | string[]>;
  };
  falsepositives: string[];
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  dataSource: LogSource;
  confidence: number; // 0-100
  generationMethod: "template" | "llm" | "hybrid";
}

export interface SigmaRuleSet {
  id: string;
  name: string;
  description: string;
  rules: SigmaRule[];
  createdAt: number;
  source: "emulation" | "gap_analysis" | "threat_actor" | "manual";
  sourceId?: string;
  totalRules: number;
  byLevel: Record<SigmaLevel, number>;
  byTactic: Record<string, number>;
  byLogSource: Record<string, number>;
}

export interface EmulationInput {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  procedure?: string;
  tools?: string[];
  detectionGap?: boolean;
  observedArtifacts?: string[];
}

// ─── ATT&CK Technique → Sigma Template Mappings ────────────────────

interface TechniqueTemplate {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  logSource: LogSource;
  logsource: { category: string; product: string; service?: string };
  detection: {
    selection: Record<string, string | string[]>;
    condition: string;
    filter?: Record<string, string | string[]>;
  };
  level: SigmaLevel;
  falsepositives: string[];
  references: string[];
}

const TECHNIQUE_TEMPLATES: TechniqueTemplate[] = [
  // ── Initial Access ──
  {
    techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access",
    logSource: "file_event",
    logsource: { category: "file_event", product: "windows" },
    detection: {
      selection: {
        TargetFilename: ["*.hta", "*.js", "*.jse", "*.vbs", "*.vbe", "*.wsf", "*.wsh", "*.scr", "*.pif", "*.lnk", "*.iso", "*.img"],
        EventType: "creation",
      },
      filter: { Image: ["*\\explorer.exe"] },
      condition: "selection and not filter",
    },
    level: "high", falsepositives: ["Legitimate file downloads"], references: ["https://attack.mitre.org/techniques/T1566/001/"],
  },
  // ── Execution ──
  {
    techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution",
    logSource: "powershell",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: ["*\\powershell.exe", "*\\pwsh.exe"],
        CommandLine: ["*-enc*", "*-encodedcommand*", "*-nop*", "*-noni*", "*bypass*", "*iex*", "*invoke-expression*", "*downloadstring*", "*downloadfile*", "*webclient*", "*start-bitstransfer*"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Administrative scripts", "Software installation"], references: ["https://attack.mitre.org/techniques/T1059/001/"],
  },
  {
    techniqueId: "T1059.003", techniqueName: "Windows Command Shell", tactic: "execution",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        ParentImage: ["*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe", "*\\mshta.exe"],
        Image: "*\\cmd.exe",
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Legitimate Office macros"], references: ["https://attack.mitre.org/techniques/T1059/003/"],
  },
  {
    techniqueId: "T1047", techniqueName: "Windows Management Instrumentation", tactic: "execution",
    logSource: "wmi_event",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: "*\\wmic.exe",
        CommandLine: ["*process*call*create*", "*node:*", "*/namespace*", "*shadowcopy*delete*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate WMI administration"], references: ["https://attack.mitre.org/techniques/T1047/"],
  },
  // ── Persistence ──
  {
    techniqueId: "T1053.005", techniqueName: "Scheduled Task", tactic: "persistence",
    logSource: "scheduled_task",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: "*\\schtasks.exe",
        CommandLine: ["*/create*", "*/change*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate scheduled tasks", "Software updates"], references: ["https://attack.mitre.org/techniques/T1053/005/"],
  },
  {
    techniqueId: "T1547.001", techniqueName: "Registry Run Keys / Startup Folder", tactic: "persistence",
    logSource: "registry_event",
    logsource: { category: "registry_set", product: "windows" },
    detection: {
      selection: {
        TargetObject: [
          "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
          "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
          "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
          "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\*",
        ],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate software installation"], references: ["https://attack.mitre.org/techniques/T1547/001/"],
  },
  {
    techniqueId: "T1543.003", techniqueName: "Windows Service", tactic: "persistence",
    logSource: "service_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: "*\\sc.exe",
        CommandLine: ["*create*", "*config*binpath*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate service installation"], references: ["https://attack.mitre.org/techniques/T1543/003/"],
  },
  // ── Privilege Escalation ──
  {
    techniqueId: "T1548.002", techniqueName: "Bypass User Account Control", tactic: "privilege-escalation",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        IntegrityLevel: "High",
        Image: ["*\\fodhelper.exe", "*\\computerdefaults.exe", "*\\sdclt.exe", "*\\eventvwr.exe", "*\\cmstp.exe"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Legitimate use of auto-elevating binaries"], references: ["https://attack.mitre.org/techniques/T1548/002/"],
  },
  // ── Defense Evasion ──
  {
    techniqueId: "T1055", techniqueName: "Process Injection", tactic: "defense-evasion",
    logSource: "process_creation",
    logsource: { category: "process_access", product: "windows" },
    detection: {
      selection: {
        GrantedAccess: ["0x1F0FFF", "0x1F1FFF", "0x143A", "0x1410"],
        CallTrace: ["*VirtualAllocEx*", "*WriteProcessMemory*", "*NtWriteVirtualMemory*"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Debugging tools", "Security products"], references: ["https://attack.mitre.org/techniques/T1055/"],
  },
  {
    techniqueId: "T1070.001", techniqueName: "Clear Windows Event Logs", tactic: "defense-evasion",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: ["*\\wevtutil.exe"],
        CommandLine: ["*cl *", "*clear-log*"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Legitimate log maintenance"], references: ["https://attack.mitre.org/techniques/T1070/001/"],
  },
  {
    techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "defense-evasion",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        CommandLine: ["*Set-MpPreference*-DisableRealtimeMonitoring*$true*", "*sc*stop*WinDefend*", "*net*stop*MsMpSvc*", "*Uninstall-WindowsFeature*Windows-Defender*"],
      },
      condition: "selection",
    },
    level: "critical", falsepositives: ["Legitimate AV management"], references: ["https://attack.mitre.org/techniques/T1562/001/"],
  },
  // ── Credential Access ──
  {
    techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access",
    logSource: "process_creation",
    logsource: { category: "process_access", product: "windows" },
    detection: {
      selection: {
        TargetImage: "*\\lsass.exe",
        GrantedAccess: ["0x1010", "0x1038", "0x1F0FFF", "0x1F1FFF"],
      },
      filter: {
        SourceImage: ["*\\MsMpEng.exe", "*\\csrss.exe", "*\\wininit.exe", "*\\wmiprvse.exe"],
      },
      condition: "selection and not filter",
    },
    level: "critical", falsepositives: ["Security products accessing LSASS"], references: ["https://attack.mitre.org/techniques/T1003/001/"],
  },
  {
    techniqueId: "T1003.003", techniqueName: "NTDS", tactic: "credential-access",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        CommandLine: ["*ntdsutil*", "*vssadmin*create*shadow*", "*copy*\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\Windows\\NTDS\\ntds.dit*"],
      },
      condition: "selection",
    },
    level: "critical", falsepositives: ["Legitimate AD backup procedures"], references: ["https://attack.mitre.org/techniques/T1003/003/"],
  },
  {
    techniqueId: "T1110", techniqueName: "Brute Force", tactic: "credential-access",
    logSource: "authentication",
    logsource: { category: "authentication", product: "windows", service: "security" },
    detection: {
      selection: {
        EventID: ["4625"],
      },
      condition: "selection | count(TargetUserName) by SourceNetworkAddress > 10",
    },
    level: "high", falsepositives: ["Misconfigured service accounts", "Password spraying tools in testing"], references: ["https://attack.mitre.org/techniques/T1110/"],
  },
  // ── Discovery ──
  {
    techniqueId: "T1087.002", techniqueName: "Domain Account Discovery", tactic: "discovery",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: ["*\\net.exe", "*\\net1.exe"],
        CommandLine: ["*user*/domain*", "*group*/domain*", "*localgroup*administrators*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate administration"], references: ["https://attack.mitre.org/techniques/T1087/002/"],
  },
  {
    techniqueId: "T1018", techniqueName: "Remote System Discovery", tactic: "discovery",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        CommandLine: ["*nltest*/dclist*", "*dsquery*computer*", "*net*view*", "*arp*-a*", "*nbtstat*-n*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Network troubleshooting"], references: ["https://attack.mitre.org/techniques/T1018/"],
  },
  // ── Lateral Movement ──
  {
    techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares", tactic: "lateral-movement",
    logSource: "network_connection",
    logsource: { category: "network_connection", product: "windows" },
    detection: {
      selection: {
        DestinationPort: ["445"],
        Initiated: "true",
      },
      filter: {
        Image: ["*\\svchost.exe", "*\\System"],
      },
      condition: "selection and not filter",
    },
    level: "medium", falsepositives: ["Legitimate file sharing", "Domain operations"], references: ["https://attack.mitre.org/techniques/T1021/002/"],
  },
  {
    techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol", tactic: "lateral-movement",
    logSource: "authentication",
    logsource: { category: "authentication", product: "windows", service: "security" },
    detection: {
      selection: {
        EventID: ["4624"],
        LogonType: "10",
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate remote administration"], references: ["https://attack.mitre.org/techniques/T1021/001/"],
  },
  // ── Collection ──
  {
    techniqueId: "T1560.001", techniqueName: "Archive via Utility", tactic: "collection",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: ["*\\7z.exe", "*\\7za.exe", "*\\rar.exe", "*\\winrar.exe", "*\\zip.exe"],
        CommandLine: ["*a *", "*-r*"],
      },
      condition: "selection",
    },
    level: "medium", falsepositives: ["Legitimate archiving operations"], references: ["https://attack.mitre.org/techniques/T1560/001/"],
  },
  // ── Exfiltration ──
  {
    techniqueId: "T1048.003", techniqueName: "Exfiltration Over Unencrypted Protocol", tactic: "exfiltration",
    logSource: "network_connection",
    logsource: { category: "network_connection", product: "windows" },
    detection: {
      selection: {
        DestinationPort: ["21", "80"],
        Initiated: "true",
      },
      condition: "selection | count() by Image > 100",
    },
    level: "high", falsepositives: ["Legitimate large file transfers", "Software updates"], references: ["https://attack.mitre.org/techniques/T1048/003/"],
  },
  // ── Command and Control ──
  {
    techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control",
    logSource: "dns_query",
    logsource: { category: "dns_query", product: "windows" },
    detection: {
      selection: {
        QueryName: ["*pastebin.com*", "*raw.githubusercontent.com*", "*ngrok.io*", "*cloudflare-dns.com*"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Legitimate developer tools"], references: ["https://attack.mitre.org/techniques/T1071/001/"],
  },
  {
    techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "command-and-control",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        Image: ["*\\certutil.exe", "*\\bitsadmin.exe"],
        CommandLine: ["*-urlcache*", "*-split*", "*/transfer*", "*/download*"],
      },
      condition: "selection",
    },
    level: "high", falsepositives: ["Legitimate certificate operations", "BITS transfers"], references: ["https://attack.mitre.org/techniques/T1105/"],
  },
  // ── Impact ──
  {
    techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact",
    logSource: "file_event",
    logsource: { category: "file_event", product: "windows" },
    detection: {
      selection: {
        TargetFilename: ["*.encrypted", "*.locked", "*.crypto", "*.enc", "*.crypt"],
        EventType: "creation",
      },
      condition: "selection | count() by Image > 50",
    },
    level: "critical", falsepositives: ["Legitimate encryption tools"], references: ["https://attack.mitre.org/techniques/T1486/"],
  },
  {
    techniqueId: "T1490", techniqueName: "Inhibit System Recovery", tactic: "impact",
    logSource: "process_creation",
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection: {
        CommandLine: ["*vssadmin*delete*shadows*", "*wmic*shadowcopy*delete*", "*bcdedit*/set*recoveryenabled*no*", "*wbadmin*delete*catalog*"],
      },
      condition: "selection",
    },
    level: "critical", falsepositives: ["Legitimate system maintenance"], references: ["https://attack.mitre.org/techniques/T1490/"],
  },
];

// ─── Rule Generation ───────────────────────────────────────────────

function generateRuleId(): string {
  const hex = () => Math.random().toString(16).substring(2, 6);
  return `${hex()}${hex()}-${hex()}-${hex()}-${hex()}-${hex()}${hex()}${hex()}`;
}

function todayStr(): string {
  return new Date().toISOString().split("T")[0];
}

/**
 * Generate a Sigma rule from a technique template
 */
export function generateFromTemplate(template: TechniqueTemplate, context?: { tools?: string[]; procedure?: string }): SigmaRule {
  const today = todayStr();
  const tags = [
    `attack.${template.tactic}`,
    `attack.${template.techniqueId.toLowerCase()}`,
  ];

  return {
    id: generateRuleId(),
    title: `${template.techniqueName} Detection (${template.techniqueId})`,
    status: "experimental",
    level: template.level,
    description: `Detects potential ${template.techniqueName} activity (MITRE ATT&CK ${template.techniqueId}).${context?.procedure ? ` Context: ${context.procedure}` : ""}`,
    author: "Ace C3 Sigma Engine",
    date: today,
    modified: today,
    references: template.references,
    tags,
    logsource: template.logsource,
    detection: template.detection,
    falsepositives: template.falsepositives,
    techniqueId: template.techniqueId,
    techniqueName: template.techniqueName,
    tactic: template.tactic,
    dataSource: template.logSource,
    confidence: 75,
    generationMethod: "template",
  };
}

/**
 * Generate Sigma rules from a list of emulation inputs (techniques observed or gaps found)
 */
export function generateFromEmulation(inputs: EmulationInput[]): SigmaRuleSet {
  const rules: SigmaRule[] = [];

  for (const input of inputs) {
    // Find matching template
    const template = TECHNIQUE_TEMPLATES.find(t => t.techniqueId === input.techniqueId);
    if (template) {
      const rule = generateFromTemplate(template, {
        tools: input.tools,
        procedure: input.procedure,
      });
      // Boost confidence for gap-identified rules
      if (input.detectionGap) {
        rule.level = rule.level === "medium" ? "high" : rule.level === "high" ? "critical" : rule.level;
        rule.description = `[DETECTION GAP] ${rule.description}`;
        rule.confidence = 90;
      }
      rules.push(rule);
    } else {
      // Generate a generic rule for unmapped techniques
      rules.push({
        id: generateRuleId(),
        title: `${input.techniqueName} Detection (${input.techniqueId})`,
        status: "experimental",
        level: "medium",
        description: `Generic detection rule for ${input.techniqueName} (${input.techniqueId}). Requires manual tuning for environment-specific indicators.`,
        author: "Ace C3 Sigma Engine",
        date: todayStr(),
        modified: todayStr(),
        references: [`https://attack.mitre.org/techniques/${input.techniqueId.replace(".", "/")}/`],
        tags: [`attack.${input.tactic}`, `attack.${input.techniqueId.toLowerCase()}`],
        logsource: { category: "process_creation", product: "windows" },
        detection: {
          selection: { CommandLine: "*" },
          condition: "selection",
        },
        falsepositives: ["Requires manual tuning — generic rule"],
        techniqueId: input.techniqueId,
        techniqueName: input.techniqueName,
        tactic: input.tactic,
        dataSource: "process_creation",
        confidence: 40,
        generationMethod: "template",
      });
    }
  }

  const byLevel = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byTactic: Record<string, number> = {};
  const byLogSource: Record<string, number> = {};

  for (const rule of rules) {
    byLevel[rule.level]++;
    byTactic[rule.tactic] = (byTactic[rule.tactic] || 0) + 1;
    byLogSource[rule.dataSource] = (byLogSource[rule.dataSource] || 0) + 1;
  }

  return {
    id: `srs-${generateRuleId().substring(0, 8)}`,
    name: `Emulation Rule Set — ${todayStr()}`,
    description: `Auto-generated Sigma rules from ${inputs.length} emulation technique(s)`,
    rules,
    createdAt: Date.now(),
    source: "emulation",
    totalRules: rules.length,
    byLevel,
    byTactic,
    byLogSource,
  };
}

/**
 * Generate rules for all techniques associated with a threat actor
 */
export function generateForThreatActor(
  actorName: string,
  techniques: { id: string; name: string; tactic: string }[],
): SigmaRuleSet {
  const inputs: EmulationInput[] = techniques.map(t => ({
    techniqueId: t.id,
    techniqueName: t.name,
    tactic: t.tactic,
  }));

  const ruleSet = generateFromEmulation(inputs);
  ruleSet.name = `Threat Actor Detection — ${actorName}`;
  ruleSet.description = `Sigma rules targeting ${actorName} TTPs (${techniques.length} techniques)`;
  ruleSet.source = "threat_actor";
  return ruleSet;
}

// ─── Export Formats ────────────────────────────────────────────────

/**
 * Export a Sigma rule to YAML format
 */
export function exportToSigmaYaml(rule: SigmaRule): string {
  const selectionEntries = Object.entries(rule.detection.selection)
    .map(([key, val]) => {
      if (Array.isArray(val)) {
        return `      ${key}:\n${val.map(v => `        - '${v}'`).join("\n")}`;
      }
      return `      ${key}: '${val}'`;
    })
    .join("\n");

  const filterSection = rule.detection.filter
    ? `\n    filter:\n${Object.entries(rule.detection.filter)
        .map(([key, val]) => {
          if (Array.isArray(val)) {
            return `      ${key}:\n${val.map(v => `        - '${v}'`).join("\n")}`;
          }
          return `      ${key}: '${val}'`;
        })
        .join("\n")}`
    : "";

  return `title: ${rule.title}
id: ${rule.id}
status: ${rule.status}
level: ${rule.level}
description: |
  ${rule.description}
author: ${rule.author}
date: ${rule.date}
modified: ${rule.modified}
references:
${rule.references.map(r => `  - ${r}`).join("\n")}
tags:
${rule.tags.map(t => `  - ${t}`).join("\n")}
logsource:
  category: ${rule.logsource.category}
  product: ${rule.logsource.product}${rule.logsource.service ? `\n  service: ${rule.logsource.service}` : ""}
detection:
  selection:
${selectionEntries}${filterSection}
  condition: ${rule.detection.condition}
falsepositives:
${rule.falsepositives.map(f => `  - ${f}`).join("\n")}`;
}

/**
 * Export a Sigma rule to Splunk SPL format
 */
export function exportToSplunkSPL(rule: SigmaRule): string {
  const searchTerms = Object.entries(rule.detection.selection)
    .map(([key, val]) => {
      if (Array.isArray(val)) {
        return `(${val.map(v => `${key}="${v}"`).join(" OR ")})`;
      }
      return `${key}="${val}"`;
    })
    .join(" ");

  const filterTerms = rule.detection.filter
    ? " NOT " + Object.entries(rule.detection.filter)
        .map(([key, val]) => {
          if (Array.isArray(val)) {
            return `(${val.map(v => `${key}="${v}"`).join(" OR ")})`;
          }
          return `${key}="${val}"`;
        })
        .join(" NOT ")
    : "";

  return `\`\`\` ${rule.title} — ${rule.techniqueId} \`\`\`
index=* sourcetype=WinEventLog:* OR sourcetype=Sysmon
| search ${searchTerms}${filterTerms}
| eval technique="${rule.techniqueId}", technique_name="${rule.techniqueName}", tactic="${rule.tactic}"
| stats count by host, user, Image, CommandLine, technique, technique_name
| where count > 0
| sort -count`;
}

/**
 * Export a Sigma rule to Microsoft KQL format
 */
export function exportToKQL(rule: SigmaRule): string {
  const whereClause = Object.entries(rule.detection.selection)
    .map(([key, val]) => {
      if (Array.isArray(val)) {
        const conditions = val.map(v => {
          if (v.includes("*")) {
            return `${key} matches regex "${v.replace(/\*/g, ".*")}"`;
          }
          return `${key} == "${v}"`;
        });
        return `(${conditions.join(" or ")})`;
      }
      if (typeof val === "string" && val.includes("*")) {
        return `${key} matches regex "${val.replace(/\*/g, ".*")}"`;
      }
      return `${key} == "${val}"`;
    })
    .join("\n  and ");

  const filterClause = rule.detection.filter
    ? "\n| where not (" + Object.entries(rule.detection.filter)
        .map(([key, val]) => {
          if (Array.isArray(val)) {
            return val.map(v => `${key} matches regex "${v.replace(/\*/g, ".*")}"`).join(" or ");
          }
          return `${key} matches regex "${String(val).replace(/\*/g, ".*")}"`;
        })
        .join(" or ") + ")"
    : "";

  return `// ${rule.title} — ${rule.techniqueId}
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ${whereClause}${filterClause}
| extend TechniqueId = "${rule.techniqueId}", TechniqueName = "${rule.techniqueName}", Tactic = "${rule.tactic}"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, TechniqueId, TechniqueName, Tactic
| sort by Timestamp desc`;
}

/**
 * Export a Sigma rule to Elastic EQL format
 */
export function exportToElasticEQL(rule: SigmaRule): string {
  const conditions = Object.entries(rule.detection.selection)
    .map(([key, val]) => {
      const eqlKey = key === "Image" ? "process.executable" :
        key === "CommandLine" ? "process.command_line" :
        key === "ParentImage" ? "process.parent.executable" :
        key === "TargetImage" ? "process.executable" :
        key === "TargetFilename" ? "file.path" :
        key === "TargetObject" ? "registry.path" :
        key === "DestinationPort" ? "destination.port" :
        key === "QueryName" ? "dns.question.name" :
        key;
      if (Array.isArray(val)) {
        return `${eqlKey} : (${val.map(v => `"${v}"`).join(", ")})`;
      }
      return `${eqlKey} : "${val}"`;
    })
    .join(" and\n  ");

  return `/* ${rule.title} — ${rule.techniqueId} */
process where
  ${conditions}`;
}

/**
 * Export a rule to the specified format
 */
export function exportRule(rule: SigmaRule, format: ExportFormat): string {
  switch (format) {
    case "sigma": return exportToSigmaYaml(rule);
    case "splunk_spl": return exportToSplunkSPL(rule);
    case "kql": return exportToKQL(rule);
    case "elastic_eql": return exportToElasticEQL(rule);
    default: return exportToSigmaYaml(rule);
  }
}

/**
 * Export an entire rule set to the specified format
 */
export function exportRuleSet(ruleSet: SigmaRuleSet, format: ExportFormat): string {
  return ruleSet.rules.map(rule => exportRule(rule, format)).join("\n\n---\n\n");
}

/**
 * Get all available technique templates
 */
export function getAvailableTemplates(): { techniqueId: string; techniqueName: string; tactic: string; logSource: LogSource; level: SigmaLevel }[] {
  return TECHNIQUE_TEMPLATES.map(t => ({
    techniqueId: t.techniqueId,
    techniqueName: t.techniqueName,
    tactic: t.tactic,
    logSource: t.logSource,
    level: t.level,
  }));
}

/**
 * Get template coverage statistics
 */
export function getTemplateCoverage(): {
  totalTemplates: number;
  byTactic: Record<string, number>;
  byLogSource: Record<string, number>;
  byLevel: Record<SigmaLevel, number>;
  tactics: string[];
} {
  const byTactic: Record<string, number> = {};
  const byLogSource: Record<string, number> = {};
  const byLevel: Record<SigmaLevel, number> = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const tactics = new Set<string>();

  for (const t of TECHNIQUE_TEMPLATES) {
    byTactic[t.tactic] = (byTactic[t.tactic] || 0) + 1;
    byLogSource[t.logSource] = (byLogSource[t.logSource] || 0) + 1;
    byLevel[t.level]++;
    tactics.add(t.tactic);
  }

  return {
    totalTemplates: TECHNIQUE_TEMPLATES.length,
    byTactic,
    byLogSource,
    byLevel,
    tactics: Array.from(tactics).sort(),
  };
}
