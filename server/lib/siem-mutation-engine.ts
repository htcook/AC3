/**
 * SIEM Rule Mutation Engine — Tier 1 of the Evasion Architecture
 * ───────────────────────────────────────────────────────────────
 * Takes any command line or Sigma detection rule and generates 7+
 * evasive variants using documented mutation categories (USENIX
 * Security 2024). Then tests each variant against the original
 * detection pattern to compute a per-rule robustness score.
 *
 * Mutation categories (Uetz et al.):
 *   1. Character case mutations
 *   2. Path variation mutations
 *   3. Environment variable substitution
 *   4. Encoding mutations (Base64, hex, Unicode)
 *   5. Caret insertion (cmd.exe escape characters)
 *   6. Variable indirection
 *   7. Interpreter chaining (powershell → cmd → wscript)
 *   8. Argument reordering
 *   9. Whitespace / delimiter mutations
 *  10. String concatenation / splitting
 *
 * Created for ACE C3 — no competitor offers automated rule
 * robustness testing.
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — CORE TYPES
// ═══════════════════════════════════════════════════════════════════════

/** Identifies which mutation category was applied */
export type MutationCategory =
  | "case"
  | "path"
  | "env_var"
  | "encoding"
  | "caret"
  | "variable_indirection"
  | "interpreter_chain"
  | "argument_reorder"
  | "whitespace"
  | "string_concat";

/** A single evasive variant produced by the mutation engine */
export interface MutationVariant {
  /** The mutated command string */
  command: string;
  /** Which mutation category was applied */
  category: MutationCategory;
  /** Human-readable description of what changed */
  description: string;
  /** Whether this variant still matches the original detection rule */
  detected: boolean;
  /** Difficulty rating for a defender to detect this variant (1-5) */
  evasionDifficulty: number;
  /** MITRE ATT&CK technique ID if applicable (e.g. T1027 for encoding) */
  attackTechnique?: string;
}

/** Result of testing a single Sigma rule or detection pattern */
export interface MutationTestResult {
  /** The original command or detection pattern */
  originalCommand: string;
  /** The Sigma rule or regex pattern tested against */
  detectionPattern: string;
  /** All generated variants with their detection status */
  variants: MutationVariant[];
  /** Robustness score: % of variants still detected (0-100) */
  robustnessScore: number;
  /** Classification based on robustness score */
  robustnessClass: "robust" | "moderate" | "fragile" | "bypassed";
  /** Total variants generated */
  totalVariants: number;
  /** Number of variants that evaded detection */
  evadedCount: number;
  /** Number of variants that were still detected */
  detectedCount: number;
  /** Weakest mutation categories (those that evaded most) */
  weakestCategories: MutationCategory[];
  /** Recommendations for hardening the rule */
  hardeningTips: string[];
}

/** A parsed Sigma rule (simplified for matching) */
export interface SigmaRulePattern {
  title: string;
  id?: string;
  description?: string;
  /** Detection field → value patterns extracted from the rule */
  detectionPatterns: DetectionField[];
  /** Log source information */
  logSource: {
    category?: string;
    product?: string;
    service?: string;
  };
  /** ATT&CK tags */
  attackTags: string[];
  /** Severity level */
  level: "informational" | "low" | "medium" | "high" | "critical";
}

export interface DetectionField {
  field: string;
  /** Values to match — can be exact strings or wildcard patterns */
  values: string[];
  /** Whether the match is case-insensitive */
  caseInsensitive: boolean;
  /** Modifier applied (contains, startswith, endswith, re, etc.) */
  modifier?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — ENVIRONMENT VARIABLE MAPPINGS
// ═══════════════════════════════════════════════════════════════════════

/** Common Windows environment variable → path mappings */
const ENV_VAR_MAP: Record<string, string[]> = {
  "cmd.exe": ["%comspec%", "%COMSPEC%"],
  "C:\\Windows": ["%SystemRoot%", "%SYSTEMROOT%", "%windir%", "%WINDIR%"],
  "C:\\Windows\\System32": [
    "%SystemRoot%\\System32",
    "%windir%\\System32",
    "%SYSTEMROOT%\\System32",
  ],
  "C:\\Windows\\System32\\cmd.exe": [
    "%comspec%",
    "%SystemRoot%\\System32\\cmd.exe",
    "%windir%\\System32\\cmd.exe",
  ],
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe": [
    "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  ],
  "C:\\Users": ["%USERPROFILE%\\..", "%HOMEDRIVE%\\Users"],
  "C:\\ProgramData": ["%ProgramData%", "%ALLUSERSPROFILE%"],
  "C:\\Program Files": ["%ProgramFiles%"],
  "C:\\Program Files (x86)": ["%ProgramFiles(x86)%"],
};

/** Common Windows binary names for interpreter chaining */
const INTERPRETERS = [
  { name: "cmd.exe", prefix: "cmd.exe /c ", suffix: "" },
  { name: "powershell.exe", prefix: 'powershell.exe -Command "', suffix: '"' },
  { name: "pwsh.exe", prefix: 'pwsh.exe -Command "', suffix: '"' },
  {
    name: "wscript",
    prefix: 'wscript //e:jscript //nologo /b "',
    suffix: '"',
    needsFile: true,
  },
  {
    name: "cscript",
    prefix: 'cscript //e:jscript //nologo /b "',
    suffix: '"',
    needsFile: true,
  },
  { name: "bash", prefix: "bash -c '", suffix: "'" },
  { name: "sh", prefix: "sh -c '", suffix: "'" },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — MUTATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Category 1: Character case mutations
 * Toggles case of executable names and arguments.
 * Many Sigma rules use case-sensitive matching.
 */
export function mutateCaseVariants(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // All uppercase
  variants.push({
    command: command.toUpperCase(),
    category: "case",
    description: "Full command converted to uppercase",
    detected: false,
    evasionDifficulty: 1,
    attackTechnique: "T1036",
  });

  // Random case (alternating)
  const randomCase = command
    .split("")
    .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
    .join("");
  variants.push({
    command: randomCase,
    category: "case",
    description: "Alternating character case",
    detected: false,
    evasionDifficulty: 1,
    attackTechnique: "T1036",
  });

  // Executable name case swap (first word)
  const parts = command.split(/\s+/);
  if (parts.length > 0) {
    const swapped = [parts[0].toUpperCase(), ...parts.slice(1)].join(" ");
    if (swapped !== command) {
      variants.push({
        command: swapped,
        category: "case",
        description: "Executable name converted to uppercase",
        detected: false,
        evasionDifficulty: 1,
        attackTechnique: "T1036",
      });
    }
  }

  return variants;
}

/**
 * Category 2: Path variation mutations
 * Uses dot-dot traversal, short names, and UNC paths.
 */
export function mutatePathVariants(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // Dot-dot traversal: C:\Windows\System32\cmd.exe → C:\Windows\System32\..\System32\cmd.exe
  const dotDot = command.replace(
    /([A-Za-z]:\\[^\\]+\\)([^\\]+\\)/g,
    "$1$2..\\$2"
  );
  if (dotDot !== command) {
    variants.push({
      command: dotDot,
      category: "path",
      description: "Path with dot-dot traversal inserted",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1036.005",
    });
  }

  // Forward slashes instead of backslashes
  const forwardSlash = command.replace(/\\/g, "/");
  if (forwardSlash !== command) {
    variants.push({
      command: forwardSlash,
      category: "path",
      description: "Backslashes replaced with forward slashes",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1036.005",
    });
  }

  // Double backslashes
  const doubleBackslash = command.replace(/\\/g, "\\\\");
  if (doubleBackslash !== command) {
    variants.push({
      command: doubleBackslash,
      category: "path",
      description: "Double backslashes in path",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1036.005",
    });
  }

  // 8.3 short name simulation
  const shortName = command
    .replace(/powershell\.exe/gi, "POWERS~1.EXE")
    .replace(/cmd\.exe/gi, "CMD~1.EXE")
    .replace(/rundll32\.exe/gi, "RUNDLL~1.EXE")
    .replace(/certutil\.exe/gi, "CERTUT~1.EXE")
    .replace(/mshta\.exe/gi, "MSHTA~1.EXE")
    .replace(/wscript\.exe/gi, "WSCRIP~1.EXE")
    .replace(/cscript\.exe/gi, "CSCRIP~1.EXE")
    .replace(/regsvr32\.exe/gi, "REGSVR~1.EXE");
  if (shortName !== command) {
    variants.push({
      command: shortName,
      category: "path",
      description: "8.3 short filename format (DOS names)",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1036.005",
    });
  }

  return variants;
}

/**
 * Category 3: Environment variable substitution
 * Replaces hardcoded paths with environment variables.
 */
export function mutateEnvVarVariants(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  for (const [literal, envVars] of Object.entries(ENV_VAR_MAP)) {
    for (const envVar of envVars) {
      if (command.toLowerCase().includes(literal.toLowerCase())) {
        const regex = new RegExp(escapeRegex(literal), "gi");
        const mutated = command.replace(regex, envVar);
        if (mutated !== command) {
          variants.push({
            command: mutated,
            category: "env_var",
            description: `Replaced "${literal}" with "${envVar}"`,
            detected: false,
            evasionDifficulty: 2,
            attackTechnique: "T1027",
          });
        }
      }
    }
  }

  // %comspec% for cmd.exe specifically
  if (
    command.toLowerCase().includes("cmd.exe") ||
    command.toLowerCase().includes("cmd ")
  ) {
    const mutated = command.replace(/cmd(\.exe)?/gi, "%comspec%");
    if (mutated !== command && !variants.some((v) => v.command === mutated)) {
      variants.push({
        command: mutated,
        category: "env_var",
        description: 'Replaced "cmd.exe" with "%comspec%"',
        detected: false,
        evasionDifficulty: 2,
        attackTechnique: "T1027",
      });
    }
  }

  return variants;
}

/**
 * Category 4: Encoding mutations
 * Base64, hex, and Unicode encoding of commands or arguments.
 */
export function mutateEncodingVariants(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // PowerShell Base64 encoded command
  const b64 = Buffer.from(command, "utf16le").toString("base64");
  variants.push({
    command: `powershell.exe -EncodedCommand ${b64}`,
    category: "encoding",
    description: "PowerShell -EncodedCommand with Base64 payload",
    detected: false,
    evasionDifficulty: 2,
    attackTechnique: "T1027",
  });

  // PowerShell with -e shorthand
  variants.push({
    command: `powershell.exe -e ${b64}`,
    category: "encoding",
    description: "PowerShell -e (short flag) with Base64 payload",
    detected: false,
    evasionDifficulty: 2,
    attackTechnique: "T1027",
  });

  // Hex-encoded characters in cmd
  const hexCmd = command
    .split("")
    .map((c) => {
      if (/[a-zA-Z]/.test(c) && Math.random() > 0.5) {
        return `\\x${c.charCodeAt(0).toString(16)}`;
      }
      return c;
    })
    .join("");
  if (hexCmd !== command) {
    variants.push({
      command: hexCmd,
      category: "encoding",
      description: "Partial hex encoding of alphabetic characters",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1027",
    });
  }

  // Certutil Base64 decode pattern
  const certutilB64 = Buffer.from(command).toString("base64");
  variants.push({
    command: `cmd.exe /c "echo ${certutilB64} > %TEMP%\\e.b64 && certutil -decode %TEMP%\\e.b64 %TEMP%\\e.bat && %TEMP%\\e.bat"`,
    category: "encoding",
    description: "Certutil Base64 decode to temp file then execute",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1140",
  });

  return variants;
}

/**
 * Category 5: Caret insertion (cmd.exe escape)
 * The ^ character is an escape in cmd.exe and is stripped at runtime.
 */
export function mutateCaretVariants(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // Insert carets between every character of the executable name
  const parts = command.split(/\s+/);
  if (parts.length > 0) {
    const caretExe = parts[0].split("").join("^");
    const caretCmd = [caretExe, ...parts.slice(1)].join(" ");
    variants.push({
      command: caretCmd,
      category: "caret",
      description: "Caret insertion in executable name (cmd.exe escape)",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1027",
    });
  }

  // Insert carets in arguments
  const caretAll = command
    .split("")
    .map((c, i) => {
      if (/[a-zA-Z]/.test(c) && i % 3 === 0) return "^" + c;
      return c;
    })
    .join("");
  if (caretAll !== command) {
    variants.push({
      command: caretAll,
      category: "caret",
      description: "Sparse caret insertion throughout command",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1027",
    });
  }

  // Wrap in cmd /c with carets
  const fullCaret = `cmd.exe /c "${command.split("").join("^")}"`;
  variants.push({
    command: fullCaret,
    category: "caret",
    description: "Full command wrapped in cmd /c with caret escaping",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003",
  });

  return variants;
}

/**
 * Category 6: Variable indirection
 * Uses cmd.exe SET and CALL to build commands from variables.
 */
export function mutateVariableIndirection(
  command: string
): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // Simple SET + CALL pattern
  const parts = command.split(/\s+/);
  if (parts.length >= 2) {
    const exe = parts[0];
    const args = parts.slice(1).join(" ");
    variants.push({
      command: `cmd.exe /c "set x=${exe} && set y=${args} && call %x% %y%"`,
      category: "variable_indirection",
      description: "Command split into SET variables, executed via CALL",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1059.003",
    });
  }

  // Character-by-character variable construction
  if (command.length <= 80) {
    const setStatements = command
      .split("")
      .map((c, i) => `set c${i}=${c}`)
      .join(" && ");
    const callParts = command
      .split("")
      .map((_, i) => `%c${i}%`)
      .join("");
    variants.push({
      command: `cmd.exe /c "${setStatements} && call ${callParts}"`,
      category: "variable_indirection",
      description: "Character-by-character variable construction",
      detected: false,
      evasionDifficulty: 4,
      attackTechnique: "T1059.003",
    });
  }

  // FOR loop construction
  variants.push({
    command: `cmd.exe /c "for /f "tokens=*" %a in ('${command}') do @echo %a"`,
    category: "variable_indirection",
    description: "Command executed inside FOR /F loop",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003",
  });

  return variants;
}

/**
 * Category 7: Interpreter chaining
 * Wraps the command in a different interpreter to bypass rules
 * that match on the parent process.
 */
export function mutateInterpreterChain(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // Determine current interpreter
  const isCmd =
    command.toLowerCase().startsWith("cmd") ||
    !command.toLowerCase().startsWith("powershell");
  const isPowershell = command.toLowerCase().startsWith("powershell");

  if (isCmd && !isPowershell) {
    // Wrap cmd command in PowerShell
    variants.push({
      command: `powershell.exe -NoProfile -Command "& { ${command.replace(/"/g, '`"')} }"`,
      category: "interpreter_chain",
      description: "cmd command wrapped in PowerShell execution",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1059.001",
    });

    // Wrap in wmic
    variants.push({
      command: `wmic process call create "${command}"`,
      category: "interpreter_chain",
      description: "Command executed via WMIC process create",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1047",
    });
  }

  if (isPowershell) {
    // Wrap PowerShell in cmd
    variants.push({
      command: `cmd.exe /c "${command}"`,
      category: "interpreter_chain",
      description: "PowerShell command wrapped in cmd.exe",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1059.003",
    });
  }

  // mshta vbscript execution
  variants.push({
    command: `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""${command.replace(/"/g, '""')}"", 0:close")`,
    category: "interpreter_chain",
    description: "Command executed via mshta VBScript",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1218.005",
  });

  // rundll32 with JavaScript
  variants.push({
    command: `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("${command}")`,
    category: "interpreter_chain",
    description: "Command executed via rundll32 JavaScript",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1218.011",
  });

  return variants;
}

/**
 * Category 8: Argument reordering
 * Reorders flags and arguments where the tool accepts them in any order.
 */
export function mutateArgumentReorder(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  const parts = command.split(/\s+/);
  if (parts.length < 3) return variants;

  const exe = parts[0];
  const args = parts.slice(1);

  // Simple reverse of arguments
  const reversed = [exe, ...args.reverse()].join(" ");
  if (reversed !== command) {
    variants.push({
      command: reversed,
      category: "argument_reorder",
      description: "Arguments reversed in order",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1036",
    });
  }

  // Swap pairs of arguments
  if (args.length >= 4) {
    const swapped = [...args];
    for (let i = 0; i < swapped.length - 1; i += 2) {
      [swapped[i], swapped[i + 1]] = [swapped[i + 1], swapped[i]];
    }
    const swappedCmd = [exe, ...swapped].join(" ");
    if (swappedCmd !== command) {
      variants.push({
        command: swappedCmd,
        category: "argument_reorder",
        description: "Adjacent argument pairs swapped",
        detected: false,
        evasionDifficulty: 1,
        attackTechnique: "T1036",
      });
    }
  }

  return variants;
}

/**
 * Category 9: Whitespace / delimiter mutations
 * Extra spaces, tabs, and null bytes between tokens.
 */
export function mutateWhitespace(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // Extra spaces
  const extraSpaces = command.replace(/\s+/g, "    ");
  if (extraSpaces !== command) {
    variants.push({
      command: extraSpaces,
      category: "whitespace",
      description: "Extra spaces between tokens",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027",
    });
  }

  // Tab characters
  const tabs = command.replace(/\s+/g, "\t");
  if (tabs !== command) {
    variants.push({
      command: tabs,
      category: "whitespace",
      description: "Tab characters as delimiters",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027",
    });
  }

  // Mixed whitespace
  const mixed = command.replace(/\s+/g, " \t ");
  if (mixed !== command) {
    variants.push({
      command: mixed,
      category: "whitespace",
      description: "Mixed spaces and tabs as delimiters",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027",
    });
  }

  return variants;
}

/**
 * Category 10: String concatenation / splitting
 * Uses PowerShell or cmd string operations to build the command.
 */
export function mutateStringConcat(command: string): MutationVariant[] {
  const variants: MutationVariant[] = [];

  // PowerShell string concatenation
  const mid = Math.floor(command.length / 2);
  const part1 = command.substring(0, mid);
  const part2 = command.substring(mid);
  variants.push({
    command: `powershell.exe -NoProfile -Command "& { $a='${part1.replace(/'/g, "''")}'; $b='${part2.replace(/'/g, "''")}'; Invoke-Expression ($a+$b) }"`,
    category: "string_concat",
    description: "Command split and concatenated via PowerShell variables",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1027",
  });

  // cmd SET concatenation
  variants.push({
    command: `cmd.exe /c "set a=${part1}&& set b=${part2}&& call %a%%b%"`,
    category: "string_concat",
    description: "Command split and concatenated via cmd SET variables",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003",
  });

  // PowerShell -join operator
  const charArray = command
    .split("")
    .map((c) => c.charCodeAt(0))
    .join(",");
  variants.push({
    command: `powershell.exe -NoProfile -Command "& { IEX([char[]](${charArray}) -join '') }"`,
    category: "string_concat",
    description: "Command built from char code array via -join",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1027",
  });

  return variants;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — SIGMA RULE PARSER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Parse a simplified Sigma rule YAML into detection patterns.
 * Supports the most common Sigma detection structures:
 *   - selection with field: value
 *   - selection with field|contains, field|startswith, field|endswith
 *   - condition: selection
 */
export function parseSigmaRule(yamlContent: string): SigmaRulePattern {
  const lines = yamlContent.split("\n");
  const rule: SigmaRulePattern = {
    title: "",
    detectionPatterns: [],
    logSource: {},
    attackTags: [],
    level: "medium",
  };

  let inDetection = false;
  let inSelection = false;
  let inLogSource = false;
  let currentField = "";
  let currentModifier = "";
  let currentValues: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

    // Top-level fields
    if (line.startsWith("title:")) {
      rule.title = line.substring(6).trim().replace(/^['"]|['"]$/g, "");
    } else if (line.startsWith("id:")) {
      rule.id = line.substring(3).trim();
    } else if (line.startsWith("description:")) {
      rule.description = line.substring(12).trim().replace(/^['"]|['"]$/g, "");
    } else if (line.startsWith("level:")) {
      const lvl = line.substring(6).trim().toLowerCase();
      if (["informational", "low", "medium", "high", "critical"].includes(lvl)) {
        rule.level = lvl as SigmaRulePattern["level"];
      }
    } else if (line.startsWith("tags:")) {
      // Tags follow on subsequent lines
    } else if (trimmed.startsWith("- attack.")) {
      rule.attackTags.push(trimmed.substring(2));
    }

    // Log source section
    if (line.startsWith("logsource:")) {
      inLogSource = true;
      inDetection = false;
      inSelection = false;
      continue;
    }
    if (inLogSource && line.startsWith("  ") && !line.startsWith("    ")) {
      if (trimmed.startsWith("category:"))
        rule.logSource.category = trimmed.substring(9).trim();
      else if (trimmed.startsWith("product:"))
        rule.logSource.product = trimmed.substring(8).trim();
      else if (trimmed.startsWith("service:"))
        rule.logSource.service = trimmed.substring(8).trim();
    }
    if (inLogSource && !line.startsWith(" ") && line.length > 0 && !line.startsWith("logsource:")) {
      inLogSource = false;
    }

    // Detection section
    if (line.startsWith("detection:")) {
      inDetection = true;
      inLogSource = false;
      inSelection = false;
      continue;
    }

    if (inDetection) {
      // New selection block
      if (/^\s{4}\w/.test(line) && trimmed.includes(":") && !trimmed.startsWith("-")) {
        // Save previous field
        if (currentField && currentValues.length > 0) {
          rule.detectionPatterns.push({
            field: currentField,
            values: [...currentValues],
            caseInsensitive: true,
            modifier: currentModifier || undefined,
          });
        }

        const colonIdx = trimmed.indexOf(":");
        const fieldPart = trimmed.substring(0, colonIdx).trim();
        const valuePart = trimmed.substring(colonIdx + 1).trim();

        // Check for modifiers (field|contains, field|startswith, etc.)
        if (fieldPart.includes("|")) {
          const [field, modifier] = fieldPart.split("|");
          currentField = field;
          currentModifier = modifier;
        } else {
          currentField = fieldPart;
          currentModifier = "";
        }

        currentValues = [];
        if (valuePart && valuePart !== "") {
          currentValues.push(valuePart.replace(/^['"]|['"]$/g, ""));
        }

        inSelection = true;
      } else if (inSelection && trimmed.startsWith("- ")) {
        // List value under current field
        currentValues.push(trimmed.substring(2).replace(/^['"]|['"]$/g, ""));
      } else if (trimmed.startsWith("condition:")) {
        // Save last field
        if (currentField && currentValues.length > 0) {
          rule.detectionPatterns.push({
            field: currentField,
            values: [...currentValues],
            caseInsensitive: true,
            modifier: currentModifier || undefined,
          });
        }
        inSelection = false;
      }

      // Exit detection on non-indented line
      if (!line.startsWith(" ") && line.length > 0 && !line.startsWith("detection:")) {
        inDetection = false;
      }
    }
  }

  // Save any remaining field
  if (currentField && currentValues.length > 0) {
    rule.detectionPatterns.push({
      field: currentField,
      values: [...currentValues],
      caseInsensitive: true,
      modifier: currentModifier || undefined,
    });
  }

  return rule;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — DETECTION MATCHING ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Test whether a command string matches a detection pattern.
 * Supports exact match, contains, startswith, endswith, and regex.
 */
export function matchesDetectionPattern(
  command: string,
  pattern: DetectionField
): boolean {
  const cmdLower = pattern.caseInsensitive ? command.toLowerCase() : command;

  for (const value of pattern.values) {
    const valLower = pattern.caseInsensitive ? value.toLowerCase() : value;

    // Handle wildcards in Sigma patterns
    const hasWildcard = valLower.includes("*");

    switch (pattern.modifier) {
      case "contains":
        if (cmdLower.includes(valLower)) return true;
        break;
      case "startswith":
        if (cmdLower.startsWith(valLower)) return true;
        break;
      case "endswith":
        if (cmdLower.endsWith(valLower)) return true;
        break;
      case "re":
        try {
          const flags = pattern.caseInsensitive ? "i" : "";
          if (new RegExp(value, flags).test(command)) return true;
        } catch {
          // Invalid regex, skip
        }
        break;
      default:
        if (hasWildcard) {
          // Convert Sigma wildcard to regex
          const regexStr = "^" + valLower.replace(/\*/g, ".*") + "$";
          try {
            if (new RegExp(regexStr, "i").test(command)) return true;
          } catch {
            // Invalid pattern
          }
        } else {
          if (cmdLower.includes(valLower)) return true;
        }
    }
  }

  return false;
}

/**
 * Test a command against all detection patterns in a parsed Sigma rule.
 * Returns true if ANY pattern matches (OR logic for simplicity).
 */
export function matchesSigmaRule(
  command: string,
  rule: SigmaRulePattern
): boolean {
  if (rule.detectionPatterns.length === 0) return false;

  // Check if command matches any detection field that looks at command-line
  const cmdFields = rule.detectionPatterns.filter((p) =>
    [
      "CommandLine",
      "commandline",
      "command_line",
      "ParentCommandLine",
      "OriginalFileName",
      "Image",
      "ParentImage",
      "TargetFilename",
      "ProcessName",
    ].includes(p.field) || p.field === "selection"
  );

  if (cmdFields.length === 0) {
    // If no command-line fields, test against all patterns
    return rule.detectionPatterns.some((p) =>
      matchesDetectionPattern(command, p)
    );
  }

  return cmdFields.some((p) => matchesDetectionPattern(command, p));
}

/**
 * Test a command against a simple regex/string detection pattern.
 * Used when no Sigma rule is available — just a raw pattern.
 */
export function matchesRawPattern(
  command: string,
  pattern: string
): boolean {
  // Try as regex first
  try {
    if (new RegExp(pattern, "i").test(command)) return true;
  } catch {
    // Not a valid regex, try as substring
  }

  // Try as case-insensitive substring
  if (command.toLowerCase().includes(pattern.toLowerCase())) return true;

  return false;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════

/** Options for generating mutations */
export interface MutationOptions {
  /** Which categories to include (default: all) */
  categories?: MutationCategory[];
  /** Maximum variants per category (default: 3) */
  maxPerCategory?: number;
  /** Whether to deduplicate identical variants (default: true) */
  deduplicate?: boolean;
}

/**
 * Generate all mutation variants for a given command.
 */
export function generateMutations(
  command: string,
  options?: MutationOptions
): MutationVariant[] {
  const categories = options?.categories || ALL_CATEGORIES;
  const maxPerCat = options?.maxPerCategory || 3;
  const dedup = options?.deduplicate !== false;

  const allVariants: MutationVariant[] = [];

  const generators: Record<MutationCategory, (cmd: string) => MutationVariant[]> = {
    case: mutateCaseVariants,
    path: mutatePathVariants,
    env_var: mutateEnvVarVariants,
    encoding: mutateEncodingVariants,
    caret: mutateCaretVariants,
    variable_indirection: mutateVariableIndirection,
    interpreter_chain: mutateInterpreterChain,
    argument_reorder: mutateArgumentReorder,
    whitespace: mutateWhitespace,
    string_concat: mutateStringConcat,
  };

  for (const cat of categories) {
    const gen = generators[cat];
    if (!gen) continue;
    const variants = gen(command).slice(0, maxPerCat);
    allVariants.push(...variants);
  }

  if (dedup) {
    const seen = new Set<string>();
    return allVariants.filter((v) => {
      if (seen.has(v.command)) return false;
      seen.add(v.command);
      return true;
    });
  }

  return allVariants;
}

/**
 * Run a full mutation test against a Sigma rule.
 * Generates all variants, tests each against the rule, and computes
 * the robustness score.
 */
export function testRuleMutations(
  command: string,
  sigmaRule: SigmaRulePattern,
  options?: MutationOptions
): MutationTestResult {
  const variants = generateMutations(command, options);

  // Test each variant against the rule
  for (const variant of variants) {
    variant.detected = matchesSigmaRule(variant.command, sigmaRule);
  }

  const detectedCount = variants.filter((v) => v.detected).length;
  const evadedCount = variants.filter((v) => !v.detected).length;
  const totalVariants = variants.length;
  const robustnessScore =
    totalVariants > 0 ? Math.round((detectedCount / totalVariants) * 100) : 100;

  // Classify robustness
  let robustnessClass: MutationTestResult["robustnessClass"];
  if (robustnessScore >= 80) robustnessClass = "robust";
  else if (robustnessScore >= 50) robustnessClass = "moderate";
  else if (robustnessScore >= 20) robustnessClass = "fragile";
  else robustnessClass = "bypassed";

  // Find weakest categories
  const categoryStats = new Map<MutationCategory, { total: number; evaded: number }>();
  for (const v of variants) {
    const stat = categoryStats.get(v.category) || { total: 0, evaded: 0 };
    stat.total++;
    if (!v.detected) stat.evaded++;
    categoryStats.set(v.category, stat);
  }

  const weakestCategories: MutationCategory[] = [];
  for (const [cat, stat] of Array.from(categoryStats.entries())) {
    if (stat.evaded > 0 && stat.evaded / stat.total >= 0.5) {
      weakestCategories.push(cat);
    }
  }

  // Sort by evasion rate descending
  weakestCategories.sort((a, b) => {
    const aRate = (categoryStats.get(a)?.evaded || 0) / (categoryStats.get(a)?.total || 1);
    const bRate = (categoryStats.get(b)?.evaded || 0) / (categoryStats.get(b)?.total || 1);
    return bRate - aRate;
  });

  // Generate hardening tips
  const hardeningTips = generateHardeningTips(weakestCategories, sigmaRule);

  // Build detection pattern string for display
  const patternStr = sigmaRule.detectionPatterns
    .map((p) => `${p.field}${p.modifier ? "|" + p.modifier : ""}: ${p.values.join(", ")}`)
    .join(" AND ");

  return {
    originalCommand: command,
    detectionPattern: patternStr || sigmaRule.title,
    variants,
    robustnessScore,
    robustnessClass,
    totalVariants,
    evadedCount,
    detectedCount,
    weakestCategories,
    hardeningTips,
  };
}

/**
 * Run a mutation test against a raw regex/string pattern.
 */
export function testRawPatternMutations(
  command: string,
  pattern: string,
  options?: MutationOptions
): MutationTestResult {
  const variants = generateMutations(command, options);

  for (const variant of variants) {
    variant.detected = matchesRawPattern(variant.command, pattern);
  }

  const detectedCount = variants.filter((v) => v.detected).length;
  const evadedCount = variants.filter((v) => !v.detected).length;
  const totalVariants = variants.length;
  const robustnessScore =
    totalVariants > 0 ? Math.round((detectedCount / totalVariants) * 100) : 100;

  let robustnessClass: MutationTestResult["robustnessClass"];
  if (robustnessScore >= 80) robustnessClass = "robust";
  else if (robustnessScore >= 50) robustnessClass = "moderate";
  else if (robustnessScore >= 20) robustnessClass = "fragile";
  else robustnessClass = "bypassed";

  const categoryStats = new Map<MutationCategory, { total: number; evaded: number }>();
  for (const v of variants) {
    const stat = categoryStats.get(v.category) || { total: 0, evaded: 0 };
    stat.total++;
    if (!v.detected) stat.evaded++;
    categoryStats.set(v.category, stat);
  }

  const weakestCategories: MutationCategory[] = [];
  for (const [cat, stat] of Array.from(categoryStats.entries())) {
    if (stat.evaded > 0 && stat.evaded / stat.total >= 0.5) {
      weakestCategories.push(cat);
    }
  }

  weakestCategories.sort((a, b) => {
    const aRate = (categoryStats.get(a)?.evaded || 0) / (categoryStats.get(a)?.total || 1);
    const bRate = (categoryStats.get(b)?.evaded || 0) / (categoryStats.get(b)?.total || 1);
    return bRate - aRate;
  });

  const hardeningTips = generateHardeningTipsFromCategories(weakestCategories);

  return {
    originalCommand: command,
    detectionPattern: pattern,
    variants,
    robustnessScore,
    robustnessClass,
    totalVariants,
    evadedCount,
    detectedCount,
    weakestCategories,
    hardeningTips,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — HARDENING RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════════

function generateHardeningTips(
  weakCategories: MutationCategory[],
  rule: SigmaRulePattern
): string[] {
  const tips: string[] = [];

  // Check if rule uses case-insensitive matching
  const hasCaseInsensitive = rule.detectionPatterns.some(
    (p) => p.caseInsensitive
  );

  for (const cat of weakCategories) {
    switch (cat) {
      case "case":
        if (!hasCaseInsensitive) {
          tips.push(
            "Add case-insensitive matching to all string comparisons. Use the Sigma modifier |contains with lowercase normalization."
          );
        }
        tips.push(
          "Normalize the CommandLine field to lowercase before pattern matching in your SIEM."
        );
        break;
      case "path":
        tips.push(
          "Match on OriginalFileName or process hash instead of Image path to defeat path traversal and 8.3 short names."
        );
        tips.push(
          "Normalize paths by resolving symlinks and dot-dot sequences before matching."
        );
        break;
      case "env_var":
        tips.push(
          "Expand environment variables in the CommandLine field before applying detection rules."
        );
        tips.push(
          "Add %comspec%, %SystemRoot%, and other common env vars as additional detection patterns."
        );
        break;
      case "encoding":
        tips.push(
          "Add detection for -EncodedCommand, -e, and -enc PowerShell flags as separate rules."
        );
        tips.push(
          "Decode Base64 content in CommandLine before matching against patterns."
        );
        break;
      case "caret":
        tips.push(
          "Strip caret (^) characters from CommandLine before pattern matching."
        );
        tips.push(
          "Add a preprocessing step to remove cmd.exe escape characters."
        );
        break;
      case "variable_indirection":
        tips.push(
          "Monitor for suspicious SET+CALL patterns in cmd.exe command lines."
        );
        tips.push(
          "Add detection for command-line strings containing multiple SET statements followed by CALL."
        );
        break;
      case "interpreter_chain":
        tips.push(
          "Add detection rules for mshta, wscript, cscript, and rundll32 executing arbitrary commands."
        );
        tips.push(
          "Monitor parent-child process relationships to detect interpreter chaining."
        );
        break;
      case "argument_reorder":
        tips.push(
          "Use |contains modifiers for individual arguments rather than matching the full command line as a single string."
        );
        break;
      case "whitespace":
        tips.push(
          "Normalize whitespace (collapse multiple spaces/tabs to single space) before matching."
        );
        break;
      case "string_concat":
        tips.push(
          "Monitor for Invoke-Expression (IEX) and [char] array patterns in PowerShell."
        );
        tips.push(
          "Add detection for cmd.exe SET variable concatenation patterns."
        );
        break;
    }
  }

  if (tips.length === 0) {
    tips.push(
      "Rule appears robust against tested mutation categories. Consider testing with additional custom mutations."
    );
  }

  return tips;
}

function generateHardeningTipsFromCategories(
  weakCategories: MutationCategory[]
): string[] {
  // Reuse the same logic with a dummy rule
  return generateHardeningTips(weakCategories, {
    title: "",
    detectionPatterns: [],
    logSource: {},
    attackTags: [],
    level: "medium",
  });
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — CONSTANTS & HELPERS
// ═══════════════════════════════════════════════════════════════════════

export const ALL_CATEGORIES: MutationCategory[] = [
  "case",
  "path",
  "env_var",
  "encoding",
  "caret",
  "variable_indirection",
  "interpreter_chain",
  "argument_reorder",
  "whitespace",
  "string_concat",
];

export const CATEGORY_LABELS: Record<MutationCategory, string> = {
  case: "Character Case",
  path: "Path Variation",
  env_var: "Environment Variable",
  encoding: "Encoding (Base64/Hex)",
  caret: "Caret Insertion",
  variable_indirection: "Variable Indirection",
  interpreter_chain: "Interpreter Chaining",
  argument_reorder: "Argument Reordering",
  whitespace: "Whitespace/Delimiter",
  string_concat: "String Concatenation",
};

export const CATEGORY_ATTACK_TECHNIQUES: Record<MutationCategory, string> = {
  case: "T1036 — Masquerading",
  path: "T1036.005 — Match Legitimate Name or Location",
  env_var: "T1027 — Obfuscated Files or Information",
  encoding: "T1027 / T1140 — Deobfuscate/Decode",
  caret: "T1027 — Obfuscated Files or Information",
  variable_indirection: "T1059.003 — Windows Command Shell",
  interpreter_chain: "T1218 — System Binary Proxy Execution",
  argument_reorder: "T1036 — Masquerading",
  whitespace: "T1027 — Obfuscated Files or Information",
  string_concat: "T1027 — Obfuscated Files or Information",
};

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
