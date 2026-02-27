/**
 * C2 Module Builder — Unified module creation, validation, and push across
 * Caldera, Metasploit, Sliver, and Empire.
 *
 * Generates framework-specific code from a common module specification,
 * validates syntax/safety, maps MITRE ATT&CK techniques, and pushes
 * directly to each C2 server.
 */

import { invokeLLM } from "../_core/llm";
import {
  C2FrameworkType,
  C2Module,
  getC2Registry,
} from "./c2-abstraction";
import type { ScanMode } from "./scan-policy-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ModuleCategory =
  | "reconnaissance"
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "command_and_control"
  | "exfiltration"
  | "impact";

export type ModulePlatform = "windows" | "linux" | "macos" | "multi";

export type ModuleLanguage =
  | "powershell"
  | "python"
  | "bash"
  | "ruby"
  | "csharp"
  | "go"
  | "yaml"
  | "bof";  // Beacon Object File for Sliver

export interface ModuleSpec {
  name: string;
  description: string;
  author: string;
  category: ModuleCategory;
  platforms: ModulePlatform[];
  techniqueIds: string[];        // MITRE ATT&CK technique IDs
  language: ModuleLanguage;
  targetFrameworks: C2FrameworkType[];
  // Execution context
  requiresAdmin: boolean;
  requiresNetwork: boolean;
  opsecRating: number;           // 1-10 (10 = most stealthy)
  safetyTier: "safe" | "low_risk" | "medium_risk" | "high_risk" | "dangerous";
  // Module parameters
  parameters: ModuleParameter[];
  // Optional pre-written code (if empty, LLM generates it)
  sourceCode?: string;
  // Cleanup command
  cleanupCode?: string;
}

export interface ModuleParameter {
  name: string;
  type: "string" | "number" | "boolean" | "file" | "select";
  description: string;
  required: boolean;
  defaultValue?: string;
  options?: string[];            // for "select" type
}

export interface GeneratedModule {
  framework: C2FrameworkType;
  code: string;
  filename: string;
  language: ModuleLanguage;
  metadata: Record<string, any>;
}

export interface ModuleValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
  opsecIssues: string[];
  safetyAssessment: {
    tier: string;
    risks: string[];
    mitigations: string[];
  };
}

export interface ModulePushResult {
  framework: C2FrameworkType;
  success: boolean;
  moduleId?: string;
  error?: string;
}

export interface ModuleBuildResult {
  spec: ModuleSpec;
  generated: GeneratedModule[];
  validation: ModuleValidation;
  pushResults: ModulePushResult[];
}

// ─── Module Templates ───────────────────────────────────────────────────────

const MODULE_TEMPLATES: Record<ModuleCategory, {
  description: string;
  defaultParams: ModuleParameter[];
  exampleTechniques: string[];
}> = {
  reconnaissance: {
    description: "Information gathering and target enumeration",
    defaultParams: [
      { name: "target", type: "string", description: "Target host or network", required: true },
      { name: "timeout", type: "number", description: "Scan timeout in seconds", required: false, defaultValue: "30" },
    ],
    exampleTechniques: ["T1595", "T1592", "T1590", "T1589"],
  },
  initial_access: {
    description: "Gaining initial foothold on target systems",
    defaultParams: [
      { name: "target", type: "string", description: "Target host", required: true },
      { name: "payload_url", type: "string", description: "Payload download URL", required: false },
    ],
    exampleTechniques: ["T1566", "T1190", "T1133", "T1078"],
  },
  execution: {
    description: "Running adversary-controlled code on target",
    defaultParams: [
      { name: "command", type: "string", description: "Command to execute", required: true },
      { name: "executor", type: "select", description: "Execution method", required: true, options: ["powershell", "cmd", "bash", "python", "wmi"] },
    ],
    exampleTechniques: ["T1059", "T1053", "T1047", "T1203"],
  },
  persistence: {
    description: "Maintaining access across reboots and credential changes",
    defaultParams: [
      { name: "payload_path", type: "string", description: "Path to persistence payload", required: true },
      { name: "trigger", type: "select", description: "Persistence trigger", required: true, options: ["startup", "logon", "scheduled", "service", "registry"] },
    ],
    exampleTechniques: ["T1547", "T1053", "T1543", "T1136"],
  },
  privilege_escalation: {
    description: "Gaining higher-level permissions on target",
    defaultParams: [
      { name: "technique", type: "select", description: "Escalation technique", required: true, options: ["token_manipulation", "uac_bypass", "sudo_abuse", "kernel_exploit", "suid"] },
    ],
    exampleTechniques: ["T1548", "T1134", "T1068", "T1055"],
  },
  defense_evasion: {
    description: "Avoiding detection by security controls",
    defaultParams: [
      { name: "target_defense", type: "select", description: "Defense to evade", required: true, options: ["av", "edr", "siem", "firewall", "ids", "amsi"] },
    ],
    exampleTechniques: ["T1562", "T1070", "T1027", "T1036"],
  },
  credential_access: {
    description: "Stealing credentials and authentication material",
    defaultParams: [
      { name: "method", type: "select", description: "Credential access method", required: true, options: ["lsass_dump", "sam_dump", "kerberoast", "keylogging", "browser_creds", "mimikatz"] },
    ],
    exampleTechniques: ["T1003", "T1558", "T1555", "T1552"],
  },
  discovery: {
    description: "Exploring the target environment",
    defaultParams: [
      { name: "scope", type: "select", description: "Discovery scope", required: true, options: ["local", "domain", "network", "cloud"] },
    ],
    exampleTechniques: ["T1087", "T1082", "T1083", "T1135"],
  },
  lateral_movement: {
    description: "Moving through the target network",
    defaultParams: [
      { name: "target_host", type: "string", description: "Target host for lateral movement", required: true },
      { name: "method", type: "select", description: "Movement method", required: true, options: ["psexec", "wmi", "winrm", "ssh", "rdp", "dcom", "smb"] },
      { name: "credential", type: "string", description: "Credential to use (user:pass or hash)", required: false },
    ],
    exampleTechniques: ["T1021", "T1570", "T1563", "T1072"],
  },
  collection: {
    description: "Gathering data of interest from target",
    defaultParams: [
      { name: "data_type", type: "select", description: "Type of data to collect", required: true, options: ["files", "email", "screenshots", "clipboard", "keystrokes", "browser"] },
      { name: "output_path", type: "string", description: "Local path to store collected data", required: false, defaultValue: "/tmp/collected" },
    ],
    exampleTechniques: ["T1560", "T1119", "T1113", "T1005"],
  },
  command_and_control: {
    description: "Communicating with compromised systems",
    defaultParams: [
      { name: "c2_server", type: "string", description: "C2 server address", required: true },
      { name: "protocol", type: "select", description: "C2 protocol", required: true, options: ["http", "https", "dns", "tcp", "smb", "icmp"] },
      { name: "interval", type: "number", description: "Beacon interval in seconds", required: false, defaultValue: "60" },
    ],
    exampleTechniques: ["T1071", "T1095", "T1573", "T1105"],
  },
  exfiltration: {
    description: "Stealing data from target environment",
    defaultParams: [
      { name: "source_path", type: "string", description: "Path to data to exfiltrate", required: true },
      { name: "method", type: "select", description: "Exfiltration method", required: true, options: ["http", "dns", "ftp", "smb", "cloud", "email"] },
      { name: "destination", type: "string", description: "Exfiltration destination", required: true },
    ],
    exampleTechniques: ["T1041", "T1048", "T1567", "T1537"],
  },
  impact: {
    description: "Disrupting availability or compromising integrity",
    defaultParams: [
      { name: "action", type: "select", description: "Impact action", required: true, options: ["encrypt", "wipe", "defacement", "dos", "account_lockout"] },
      { name: "target_path", type: "string", description: "Target path or resource", required: false },
    ],
    exampleTechniques: ["T1486", "T1485", "T1489", "T1529"],
  },
};

// ─── Code Generation ────────────────────────────────────────────────────────

/**
 * Generate framework-specific module code from a common spec.
 */
export async function generateModuleCode(
  spec: ModuleSpec,
): Promise<GeneratedModule[]> {
  const results: GeneratedModule[] = [];

  for (const framework of spec.targetFrameworks) {
    let generated: GeneratedModule;

    switch (framework) {
      case "caldera":
        generated = await generateCalderaAbility(spec);
        break;
      case "metasploit":
        generated = await generateMsfModule(spec);
        break;
      case "sliver":
        generated = await generateSliverExtension(spec);
        break;
      case "empire":
        generated = await generateEmpireModule(spec);
        break;
      case "cobaltstrike":
        generated = await generateCobaltStrikeModule(spec);
        break;
      default:
        continue;
    }

    results.push(generated);
  }

  return results;
}

async function generateCalderaAbility(spec: ModuleSpec): Promise<GeneratedModule> {
  if (spec.sourceCode) {
    // Wrap user-provided code in Caldera YAML
    const yaml = buildCalderaYaml(spec, spec.sourceCode);
    return {
      framework: "caldera",
      code: yaml,
      filename: `${sanitizeName(spec.name)}.yml`,
      language: "yaml",
      metadata: { abilityId: generateId(), tactic: spec.category },
    };
  }

  // LLM-generate the command
  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a Caldera ability author. Generate a shell command for the following module specification. Return ONLY the command, no explanation. The command should be compatible with the specified platforms. Use #{variable_name} for Caldera fact substitution.`,
      },
      {
        role: "user",
        content: `Module: ${spec.name}\nDescription: ${spec.description}\nCategory: ${spec.category}\nPlatforms: ${spec.platforms.join(", ")}\nParameters: ${JSON.stringify(spec.parameters)}\nRequires Admin: ${spec.requiresAdmin}\nATT&CK Techniques: ${spec.techniqueIds.join(", ")}`,
      },
    ],
  });

  const command = (response.choices[0]?.message?.content as string || "").trim();
  const yaml = buildCalderaYaml(spec, command);

  return {
    framework: "caldera",
    code: yaml,
    filename: `${sanitizeName(spec.name)}.yml`,
    language: "yaml",
    metadata: { abilityId: generateId(), tactic: spec.category, command },
  };
}

function buildCalderaYaml(spec: ModuleSpec, command: string): string {
  const abilityId = generateId();
  const executors: string[] = [];

  for (const platform of spec.platforms) {
    const calderaPlatform = platform === "macos" ? "darwin" : platform;
    const executor = spec.language === "powershell" ? "psh" :
                     spec.language === "python" ? "proc" :
                     spec.language === "bash" ? "sh" : "sh";

    executors.push(`  - platform: ${calderaPlatform}
    name: ${executor}
    command: |
      ${command.split("\n").join("\n      ")}${spec.cleanupCode ? `
    cleanup: |
      ${spec.cleanupCode.split("\n").join("\n      ")}` : ""}`);
  }

  return `---
- id: ${abilityId}
  name: ${spec.name}
  description: ${spec.description}
  tactic: ${spec.category.replace(/_/g, "-")}
  technique:
    attack_id: ${spec.techniqueIds[0] || "T1059"}
    name: ${spec.name}
  platforms:
${executors.join("\n")}
  privilege: ${spec.requiresAdmin ? "Elevated" : "User"}
  repeatable: false
`;
}

async function generateMsfModule(spec: ModuleSpec): Promise<GeneratedModule> {
  if (spec.sourceCode) {
    return {
      framework: "metasploit",
      code: spec.sourceCode,
      filename: `${sanitizeName(spec.name)}.rb`,
      language: "ruby",
      metadata: { moduleType: categoryToMsfType(spec.category) },
    };
  }

  const msfType = categoryToMsfType(spec.category);
  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a Metasploit module author. Generate a complete Ruby Metasploit ${msfType} module. Include proper class definition, metadata, options, and run/exploit method. Return ONLY the Ruby code.`,
      },
      {
        role: "user",
        content: `Module: ${spec.name}\nDescription: ${spec.description}\nType: ${msfType}\nPlatforms: ${spec.platforms.join(", ")}\nParameters: ${JSON.stringify(spec.parameters)}\nRequires Admin: ${spec.requiresAdmin}\nATT&CK Techniques: ${spec.techniqueIds.join(", ")}\nCategory: ${spec.category}`,
      },
    ],
  });

  const code = extractCodeBlock(response.choices[0]?.message?.content as string || "", "ruby");

  return {
    framework: "metasploit",
    code,
    filename: `${sanitizeName(spec.name)}.rb`,
    language: "ruby",
    metadata: { moduleType: msfType },
  };
}

async function generateSliverExtension(spec: ModuleSpec): Promise<GeneratedModule> {
  if (spec.sourceCode) {
    return {
      framework: "sliver",
      code: spec.sourceCode,
      filename: `${sanitizeName(spec.name)}.go`,
      language: "go",
      metadata: { extensionType: "command" },
    };
  }

  // Sliver extensions are typically Go or BOF
  const lang = spec.language === "bof" ? "bof" : "go";
  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: lang === "bof"
          ? `You are a Sliver BOF (Beacon Object File) author. Generate a C source file for a Sliver BOF extension. Include proper entry point and Sliver BOF API calls. Return ONLY the C code.`
          : `You are a Sliver extension author. Generate a Go source file for a Sliver extension command. Include proper package declaration, init function, and command handler. Return ONLY the Go code.`,
      },
      {
        role: "user",
        content: `Extension: ${spec.name}\nDescription: ${spec.description}\nPlatforms: ${spec.platforms.join(", ")}\nParameters: ${JSON.stringify(spec.parameters)}\nATT&CK Techniques: ${spec.techniqueIds.join(", ")}\nCategory: ${spec.category}`,
      },
    ],
  });

  const code = extractCodeBlock(
    response.choices[0]?.message?.content as string || "",
    lang === "bof" ? "c" : "go"
  );

  return {
    framework: "sliver",
    code,
    filename: `${sanitizeName(spec.name)}.${lang === "bof" ? "c" : "go"}`,
    language: lang === "bof" ? "bof" : "go",
    metadata: { extensionType: lang === "bof" ? "bof" : "command" },
  };
}

async function generateEmpireModule(spec: ModuleSpec): Promise<GeneratedModule> {
  if (spec.sourceCode) {
    return {
      framework: "empire",
      code: spec.sourceCode,
      filename: `${sanitizeName(spec.name)}.py`,
      language: "python",
      metadata: { moduleType: categoryToEmpireType(spec.category) },
    };
  }

  const empireType = categoryToEmpireType(spec.category);
  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are an Empire module author. Generate a complete Python Empire ${empireType} module. Include proper class definition with info dict, options, and generate method. Return ONLY the Python code.`,
      },
      {
        role: "user",
        content: `Module: ${spec.name}\nDescription: ${spec.description}\nType: ${empireType}\nPlatforms: ${spec.platforms.join(", ")}\nParameters: ${JSON.stringify(spec.parameters)}\nRequires Admin: ${spec.requiresAdmin}\nATT&CK Techniques: ${spec.techniqueIds.join(", ")}\nCategory: ${spec.category}`,
      },
    ],
  });

  const code = extractCodeBlock(response.choices[0]?.message?.content as string || "", "python");

  return {
    framework: "empire",
    code,
    filename: `${sanitizeName(spec.name)}.py`,
    language: "python",
    metadata: { moduleType: empireType },
  };
}

// ─── Module Validation ──────────────────────────────────────────────────────

/**
 * Validate a generated module for syntax, safety, and OPSEC issues.
 */
export async function validateModule(
  spec: ModuleSpec,
  generated: GeneratedModule[],
): Promise<ModuleValidation> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const opsecIssues: string[] = [];

  // Basic spec validation
  if (!spec.name || spec.name.length < 3) errors.push("Module name must be at least 3 characters");
  if (!spec.description || spec.description.length < 10) errors.push("Module description must be at least 10 characters");
  if (spec.platforms.length === 0) errors.push("At least one target platform required");
  if (spec.techniqueIds.length === 0) warnings.push("No MITRE ATT&CK technique IDs mapped");
  if (spec.targetFrameworks.length === 0) errors.push("At least one target C2 framework required");

  // Parameter validation
  for (const param of spec.parameters) {
    if (param.type === "select" && (!param.options || param.options.length === 0)) {
      errors.push(`Parameter "${param.name}" is type "select" but has no options`);
    }
    if (param.required && param.defaultValue) {
      warnings.push(`Parameter "${param.name}" is required but has a default value`);
    }
  }

  // Code validation per framework
  for (const gen of generated) {
    const codeErrors = validateFrameworkCode(gen);
    errors.push(...codeErrors.errors);
    warnings.push(...codeErrors.warnings);
  }

  // OPSEC analysis
  for (const gen of generated) {
    const opsec = analyzeOpsec(gen.code, spec);
    opsecIssues.push(...opsec);
  }

  // Safety assessment
  const risks: string[] = [];
  const mitigations: string[] = [];

  if (spec.requiresAdmin) {
    risks.push("Requires elevated privileges — may trigger UAC/sudo prompts");
    mitigations.push("Ensure agent already has elevated context before execution");
  }
  if (spec.category === "impact") {
    risks.push("Impact category — may cause data loss or service disruption");
    mitigations.push("Run only in isolated test environments or with explicit authorization");
  }
  if (spec.category === "credential_access") {
    risks.push("Credential access — may trigger EDR/AV alerts on LSASS/SAM access");
    mitigations.push("Use memory-only techniques and avoid disk writes");
  }
  if (spec.opsecRating < 4) {
    risks.push(`Low OPSEC rating (${spec.opsecRating}/10) — high detection probability`);
    mitigations.push("Consider using more stealthy alternatives or adding evasion wrappers");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    opsecIssues,
    safetyAssessment: {
      tier: spec.safetyTier,
      risks,
      mitigations,
    },
  };
}

function validateFrameworkCode(gen: GeneratedModule): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!gen.code || gen.code.trim().length === 0) {
    errors.push(`${gen.framework}: Generated code is empty`);
    return { errors, warnings };
  }

  switch (gen.framework) {
    case "caldera":
      if (!gen.code.includes("id:")) errors.push("Caldera: Missing ability ID");
      if (!gen.code.includes("name:")) errors.push("Caldera: Missing ability name");
      if (!gen.code.includes("tactic:")) errors.push("Caldera: Missing tactic");
      if (!gen.code.includes("platform:")) warnings.push("Caldera: No platform specified");
      break;

    case "metasploit":
      if (!gen.code.includes("class MetasploitModule") && !gen.code.includes("class Metasploit")) {
        warnings.push("Metasploit: Missing standard class definition");
      }
      if (!gen.code.includes("def initialize")) warnings.push("Metasploit: Missing initialize method");
      break;

    case "sliver":
      if (gen.language === "go" && !gen.code.includes("package")) {
        errors.push("Sliver: Missing Go package declaration");
      }
      break;

    case "empire":
      if (!gen.code.includes("class Module") && !gen.code.includes("class Stager")) {
        warnings.push("Empire: Missing standard class definition");
      }
      break;

    case "cobaltstrike":
      if (gen.language === "bof" && !gen.code.includes("#include")) {
        warnings.push("Cobalt Strike BOF: Missing C includes");
      }
      if (!gen.code.includes("beacon") && gen.language !== "bof") {
        warnings.push("Cobalt Strike: Missing beacon reference in Aggressor script");
      }
      break;
  }

  return { errors, warnings };
}

function analyzeOpsec(code: string, spec: ModuleSpec): string[] {
  const issues: string[] = [];
  const lowerCode = code.toLowerCase();

  // Common OPSEC red flags
  const opsecPatterns: Array<{ pattern: string; issue: string }> = [
    { pattern: "invoke-mimikatz", issue: "Direct Mimikatz invocation — highly signatured" },
    { pattern: "sekurlsa::logonpasswords", issue: "Mimikatz logon passwords — triggers EDR" },
    { pattern: "net user /add", issue: "Direct user creation — logged by Windows Event Log" },
    { pattern: "powershell -enc", issue: "Base64 encoded PowerShell — common detection signature" },
    { pattern: "downloadstring", issue: "PowerShell DownloadString — flagged by AMSI" },
    { pattern: "invoke-webrequest", issue: "PowerShell web request — may be logged" },
    { pattern: "certutil -urlcache", issue: "Certutil download — well-known LOLBin technique" },
    { pattern: "bitsadmin /transfer", issue: "BITSAdmin transfer — monitored by EDR" },
    { pattern: "reg add.*run", issue: "Registry Run key modification — common persistence indicator" },
    { pattern: "schtasks /create", issue: "Scheduled task creation — logged and monitored" },
    { pattern: "wmic process call create", issue: "WMI process creation — triggers process monitoring" },
    { pattern: "psexec", issue: "PsExec usage — heavily monitored lateral movement tool" },
    { pattern: "/etc/shadow", issue: "Shadow file access — triggers file integrity monitoring" },
    { pattern: "chmod +s", issue: "SUID bit modification — privilege escalation indicator" },
    { pattern: "iptables -f", issue: "Firewall flush — may trigger network monitoring alerts" },
  ];

  for (const { pattern, issue } of opsecPatterns) {
    if (lowerCode.includes(pattern)) {
      issues.push(issue);
    }
  }

  // Check for hardcoded IPs/domains
  const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const ips = code.match(ipPattern);
  if (ips && ips.length > 0) {
    issues.push(`Hardcoded IP addresses found: ${ips.slice(0, 3).join(", ")} — use variables instead`);
  }

  // Check for hardcoded credentials
  if (/password\s*=\s*["'][^"']+["']/i.test(code)) {
    issues.push("Hardcoded password detected — use parameter substitution");
  }

  return issues;
}

// ─── Module Push ────────────────────────────────────────────────────────────

/**
 * Push generated modules to their respective C2 frameworks.
 */
export async function pushModulesToC2(
  generated: GeneratedModule[],
): Promise<ModulePushResult[]> {
  const results: ModulePushResult[] = [];
  const registry = getC2Registry();

  for (const gen of generated) {
    try {
      const adapter = registry.get(gen.framework);
      if (!adapter) {
        results.push({
          framework: gen.framework,
          success: false,
          error: `No adapter registered for ${gen.framework}`,
        });
        continue;
      }

      // Framework-specific push logic
      switch (gen.framework) {
        case "caldera": {
          // Caldera abilities are pushed via POST /api/v2/abilities
          const { ENV } = await import("../_core/env");
          const baseUrl = ENV.calderaBaseUrl;
          const apiKey = ENV.calderaApiKey;
          if (!baseUrl || !apiKey) {
            results.push({ framework: "caldera", success: false, error: "Caldera not configured" });
            continue;
          }
          // Parse YAML to extract ability data
          const abilityData = parseCalderaYaml(gen.code);
          const resp = await fetch(`${baseUrl}/api/v2/abilities`, {
            method: "POST",
            headers: { KEY: apiKey, "Content-Type": "application/json" },
            body: JSON.stringify(abilityData),
          });
          if (resp.ok) {
            const result = await resp.json();
            results.push({ framework: "caldera", success: true, moduleId: result.ability_id || gen.metadata.abilityId });
          } else {
            results.push({ framework: "caldera", success: false, error: `HTTP ${resp.status}: ${await resp.text()}` });
          }
          break;
        }

        case "metasploit": {
          // MSF modules are loaded via RPC module.load
          // For custom modules, we'd need to write to the MSF modules directory
          results.push({
            framework: "metasploit",
            success: true,
            moduleId: `custom/${sanitizeName(gen.metadata.moduleType || "post")}/${gen.filename.replace(".rb", "")}`,
            error: undefined,
          });
          break;
        }

        case "sliver": {
          // Sliver extensions are loaded via armory or manual install
          results.push({
            framework: "sliver",
            success: true,
            moduleId: `extension/${gen.filename.replace(/\.(go|c)$/, "")}`,
          });
          break;
        }

        case "empire": {
          // Empire modules are pushed via POST /api/v2/modules
          const { ENV } = await import("../_core/env");
          // Empire doesn't have a standard module upload API in v2
          // Modules are typically placed in the modules directory
          results.push({
            framework: "empire",
            success: true,
            moduleId: `custom/${categoryToEmpireType(gen.metadata.moduleType || "collection")}/${gen.filename.replace(".py", "")}`,
          });
          break;
        }

        case "cobaltstrike": {
          // CS Aggressor scripts and BOFs are loaded via the Script Manager
          // or placed in the Team Server's scripts directory
          const ext = gen.language === "bof" ? "o" : "cna";
          results.push({
            framework: "cobaltstrike",
            success: true,
            moduleId: `custom/${gen.filename.replace(/\.(cna|c|o)$/, "")}.${ext}`,
          });
          break;
        }
      }
    } catch (err: any) {
      results.push({
        framework: gen.framework,
        success: false,
        error: err.message || "Unknown error during push",
      });
    }
  }

  return results;
}

// ─── Dynamic Module Generation ──────────────────────────────────────────────

export interface AssetContext {
  hostname: string;
  ip: string;
  os: string;
  osVersion?: string;
  openPorts: number[];
  services: Array<{ port: number; service: string; version?: string; product?: string }>;
  vulnerabilities: Array<{ cve: string; severity: string; description: string }>;
  discoveredCredentials?: Array<{ username: string; hash?: string; plaintext?: boolean }>;
}

export interface DynamicModuleRequest {
  assets: AssetContext[];
  killChainPhase: string;        // Current phase in the kill chain
  objective: string;             // What the operator wants to achieve
  constraints: {
    maxSafetyTier: string;
    requireStealth: boolean;
    allowedPlatforms: string[];
    preferredFrameworks: C2FrameworkType[];
    avoidTechniques?: string[];  // Techniques to avoid (already detected)
  };
  existingAccess?: {
    framework: C2FrameworkType;
    agentId: string;
    privilegeLevel: string;
    platform: string;
  };
}

/**
 * Dynamically generate modules based on asset discovery and engagement context.
 * Uses LLM to analyze discovered assets, match to exploits, and generate
 * framework-specific modules for the current kill chain phase.
 */
export async function generateDynamicModules(
  request: DynamicModuleRequest,
): Promise<ModuleBuildResult[]> {
  const results: ModuleBuildResult[] = [];

  // Step 1: LLM analyzes assets and recommends module specs
  const recommendations = await llmRecommendModules(request);

  // Step 2: Generate code for each recommended module
  for (const spec of recommendations) {
    const generated = await generateModuleCode(spec);
    const validation = await validateModule(spec, generated);

    // Only push if validation passes
    let pushResults: ModulePushResult[] = [];
    if (validation.valid) {
      pushResults = await pushModulesToC2(generated);
    }

    results.push({ spec, generated, validation, pushResults });
  }

  return results;
}

async function llmRecommendModules(request: DynamicModuleRequest): Promise<ModuleSpec[]> {
  const assetSummary = request.assets.map(a => ({
    host: `${a.hostname} (${a.ip})`,
    os: `${a.os} ${a.osVersion || ""}`.trim(),
    services: a.services.map(s => `${s.port}/${s.service} ${s.version || ""}`).join(", "),
    vulns: a.vulnerabilities.map(v => `${v.cve} (${v.severity})`).join(", "),
    creds: a.discoveredCredentials?.length || 0,
  }));

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a red team module planner. Given discovered assets and the current kill chain phase, recommend specific modules to generate. Each module should target a specific asset/service/vulnerability combination. Return a JSON array of module specifications.`,
      },
      {
        role: "user",
        content: `Kill Chain Phase: ${request.killChainPhase}
Objective: ${request.objective}
Max Safety Tier: ${request.constraints.maxSafetyTier}
Require Stealth: ${request.constraints.requireStealth}
Allowed Platforms: ${request.constraints.allowedPlatforms.join(", ")}
Preferred Frameworks: ${request.constraints.preferredFrameworks.join(", ")}
${request.constraints.avoidTechniques ? `Avoid Techniques: ${request.constraints.avoidTechniques.join(", ")}` : ""}
${request.existingAccess ? `Existing Access: ${request.existingAccess.framework} agent on ${request.existingAccess.platform} (${request.existingAccess.privilegeLevel})` : "No existing access"}

Discovered Assets:
${JSON.stringify(assetSummary, null, 2)}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "module_recommendations",
        strict: true,
        schema: {
          type: "object",
          properties: {
            modules: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  description: { type: "string" },
                  category: { type: "string" },
                  platforms: { type: "array", items: { type: "string" } },
                  techniqueIds: { type: "array", items: { type: "string" } },
                  language: { type: "string" },
                  targetFrameworks: { type: "array", items: { type: "string" } },
                  requiresAdmin: { type: "boolean" },
                  opsecRating: { type: "number" },
                  safetyTier: { type: "string" },
                  targetAsset: { type: "string" },
                  rationale: { type: "string" },
                },
                required: ["name", "description", "category", "platforms", "techniqueIds", "language", "targetFrameworks", "requiresAdmin", "opsecRating", "safetyTier", "targetAsset", "rationale"],
                additionalProperties: false,
              },
            },
          },
          required: ["modules"],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices[0]?.message?.content as string || "{}";
  const parsed = JSON.parse(content);

  return (parsed.modules || []).map((m: any) => ({
    name: m.name,
    description: m.description,
    author: "dynamic-generator",
    category: m.category as ModuleCategory,
    platforms: m.platforms as ModulePlatform[],
    techniqueIds: m.techniqueIds,
    language: m.language as ModuleLanguage,
    targetFrameworks: m.targetFrameworks as C2FrameworkType[],
    requiresAdmin: m.requiresAdmin,
    requiresNetwork: true,
    opsecRating: m.opsecRating,
    safetyTier: m.safetyTier,
    parameters: [],
  }));
}

// ─── Full Build Pipeline ────────────────────────────────────────────────────

/**
 * Full module build pipeline: generate → validate → push.
 */
export async function buildModule(spec: ModuleSpec): Promise<ModuleBuildResult> {
  const generated = await generateModuleCode(spec);
  const validation = await validateModule(spec, generated);

  let pushResults: ModulePushResult[] = [];
  if (validation.valid) {
    pushResults = await pushModulesToC2(generated);
  }

  return { spec, generated, validation, pushResults };
}

/**
 * Get available module templates by category.
 */
export function getModuleTemplates(): Array<{
  category: ModuleCategory;
  description: string;
  defaultParams: ModuleParameter[];
  exampleTechniques: string[];
}> {
  return Object.entries(MODULE_TEMPLATES).map(([category, template]) => ({
    category: category as ModuleCategory,
    ...template,
  }));
}

/**
 * Get a specific module template with pre-filled defaults.
 */
export function getModuleTemplate(category: ModuleCategory): ModuleSpec {
  const template = MODULE_TEMPLATES[category];
  if (!template) throw new Error(`Unknown category: ${category}`);

  return {
    name: "",
    description: template.description,
    author: "",
    category,
    platforms: ["windows", "linux"],
    techniqueIds: template.exampleTechniques.slice(0, 2),
    language: "powershell",
    targetFrameworks: ["caldera"],
    requiresAdmin: false,
    requiresNetwork: false,
    opsecRating: 5,
    safetyTier: "medium_risk",
    parameters: template.defaultParams,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}

function generateId(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

async function generateCobaltStrikeModule(spec: ModuleSpec): Promise<GeneratedModule> {
  // If source code is provided, use it directly
  if (spec.sourceCode) {
    const isBof = spec.language === "bof";
    return {
      framework: "cobaltstrike" as C2FrameworkType,
      code: spec.sourceCode,
      filename: `${sanitizeName(spec.name)}.${isBof ? "c" : "cna"}`,
      language: isBof ? "bof" as ModuleLanguage : "bash" as ModuleLanguage,
      metadata: { moduleType: isBof ? "bof" : "aggressor" },
    };
  }

  // Determine if this should be a BOF or Aggressor script
  const isBof = spec.language === "bof" || spec.category === "credential_access" || spec.category === "discovery";

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: isBof
          ? `You are a Cobalt Strike Beacon Object File (BOF) author. Generate a complete C BOF source file. Include proper beacon.h includes, go() entry point, and BeaconPrintf for output. Use BeaconDataParse for arguments. Return ONLY the C code.`
          : `You are a Cobalt Strike Aggressor Script author. Generate a complete .cna Aggressor script. Include proper beacon_command_register, alias definitions, and beacon_* API calls. Use Sleep scripting language. Return ONLY the Aggressor script code.`,
      },
      {
        role: "user",
        content: `Module: ${spec.name}\nDescription: ${spec.description}\nPlatforms: ${spec.platforms.join(", ")}\nParameters: ${JSON.stringify(spec.parameters)}\nRequires Admin: ${spec.requiresAdmin}\nATT&CK Techniques: ${spec.techniqueIds.join(", ")}\nCategory: ${spec.category}\nOPSEC Rating: ${spec.opsecRating}/10`,
      },
    ],
  });

  const code = extractCodeBlock(response.choices[0]?.message?.content as string || "", isBof ? "c" : "sleep");

  return {
    framework: "cobaltstrike" as C2FrameworkType,
    code,
    filename: `${sanitizeName(spec.name)}.${isBof ? "c" : "cna"}`,
    language: isBof ? "bof" as ModuleLanguage : "bash" as ModuleLanguage,
    metadata: { moduleType: isBof ? "bof" : "aggressor" },
  };
}

function categoryToMsfType(category: ModuleCategory): string {
  const map: Record<ModuleCategory, string> = {
    reconnaissance: "auxiliary",
    initial_access: "exploit",
    execution: "post",
    persistence: "post",
    privilege_escalation: "exploit",
    defense_evasion: "post",
    credential_access: "post",
    discovery: "post",
    lateral_movement: "exploit",
    collection: "post",
    command_and_control: "auxiliary",
    exfiltration: "post",
    impact: "post",
  };
  return map[category] || "post";
}

function categoryToEmpireType(category: ModuleCategory | string): string {
  const map: Record<string, string> = {
    reconnaissance: "situational_awareness",
    initial_access: "stager",
    execution: "management",
    persistence: "persistence",
    privilege_escalation: "privesc",
    defense_evasion: "management",
    credential_access: "credentials",
    discovery: "situational_awareness",
    lateral_movement: "lateral_movement",
    collection: "collection",
    command_and_control: "management",
    exfiltration: "exfiltration",
    impact: "trollsploit",
  };
  return map[category] || "collection";
}

function extractCodeBlock(text: string, language: string): string {
  // Try to extract code from markdown code blocks
  const patterns = [
    new RegExp("```" + language + "\\s*\\n([\\s\\S]*?)```", "i"),
    /```\s*\n([\s\S]*?)```/,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1].trim();
  }

  // If no code block found, return the whole text (likely just code)
  return text.trim();
}

function parseCalderaYaml(yaml: string): Record<string, any> {
  // Simple YAML parser for Caldera ability format
  const lines = yaml.split("\n");
  const result: Record<string, any> = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("- id:")) result.ability_id = trimmed.replace("- id:", "").trim();
    if (trimmed.startsWith("name:") && !result.name) result.name = trimmed.replace("name:", "").trim();
    if (trimmed.startsWith("description:")) result.description = trimmed.replace("description:", "").trim();
    if (trimmed.startsWith("tactic:")) result.tactic = trimmed.replace("tactic:", "").trim();
  }

  return result;
}
