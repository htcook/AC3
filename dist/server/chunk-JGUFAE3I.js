// server/lib/siem-mutation-engine.ts
var ENV_VAR_MAP = {
  "cmd.exe": ["%comspec%", "%COMSPEC%"],
  "C:\\Windows": ["%SystemRoot%", "%SYSTEMROOT%", "%windir%", "%WINDIR%"],
  "C:\\Windows\\System32": [
    "%SystemRoot%\\System32",
    "%windir%\\System32",
    "%SYSTEMROOT%\\System32"
  ],
  "C:\\Windows\\System32\\cmd.exe": [
    "%comspec%",
    "%SystemRoot%\\System32\\cmd.exe",
    "%windir%\\System32\\cmd.exe"
  ],
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe": [
    "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  ],
  "C:\\Users": ["%USERPROFILE%\\..", "%HOMEDRIVE%\\Users"],
  "C:\\ProgramData": ["%ProgramData%", "%ALLUSERSPROFILE%"],
  "C:\\Program Files": ["%ProgramFiles%"],
  "C:\\Program Files (x86)": ["%ProgramFiles(x86)%"]
};
function mutateCaseVariants(command) {
  const variants = [];
  variants.push({
    command: command.toUpperCase(),
    category: "case",
    description: "Full command converted to uppercase",
    detected: false,
    evasionDifficulty: 1,
    attackTechnique: "T1036"
  });
  const randomCase = command.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join("");
  variants.push({
    command: randomCase,
    category: "case",
    description: "Alternating character case",
    detected: false,
    evasionDifficulty: 1,
    attackTechnique: "T1036"
  });
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
        attackTechnique: "T1036"
      });
    }
  }
  return variants;
}
function mutatePathVariants(command) {
  const variants = [];
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
      attackTechnique: "T1036.005"
    });
  }
  const forwardSlash = command.replace(/\\/g, "/");
  if (forwardSlash !== command) {
    variants.push({
      command: forwardSlash,
      category: "path",
      description: "Backslashes replaced with forward slashes",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1036.005"
    });
  }
  const doubleBackslash = command.replace(/\\/g, "\\\\");
  if (doubleBackslash !== command) {
    variants.push({
      command: doubleBackslash,
      category: "path",
      description: "Double backslashes in path",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1036.005"
    });
  }
  const shortName = command.replace(/powershell\.exe/gi, "POWERS~1.EXE").replace(/cmd\.exe/gi, "CMD~1.EXE").replace(/rundll32\.exe/gi, "RUNDLL~1.EXE").replace(/certutil\.exe/gi, "CERTUT~1.EXE").replace(/mshta\.exe/gi, "MSHTA~1.EXE").replace(/wscript\.exe/gi, "WSCRIP~1.EXE").replace(/cscript\.exe/gi, "CSCRIP~1.EXE").replace(/regsvr32\.exe/gi, "REGSVR~1.EXE");
  if (shortName !== command) {
    variants.push({
      command: shortName,
      category: "path",
      description: "8.3 short filename format (DOS names)",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1036.005"
    });
  }
  return variants;
}
function mutateEnvVarVariants(command) {
  const variants = [];
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
            attackTechnique: "T1027"
          });
        }
      }
    }
  }
  if (command.toLowerCase().includes("cmd.exe") || command.toLowerCase().includes("cmd ")) {
    const mutated = command.replace(/cmd(\.exe)?/gi, "%comspec%");
    if (mutated !== command && !variants.some((v) => v.command === mutated)) {
      variants.push({
        command: mutated,
        category: "env_var",
        description: 'Replaced "cmd.exe" with "%comspec%"',
        detected: false,
        evasionDifficulty: 2,
        attackTechnique: "T1027"
      });
    }
  }
  return variants;
}
function mutateEncodingVariants(command) {
  const variants = [];
  const b64 = Buffer.from(command, "utf16le").toString("base64");
  variants.push({
    command: `powershell.exe -EncodedCommand ${b64}`,
    category: "encoding",
    description: "PowerShell -EncodedCommand with Base64 payload",
    detected: false,
    evasionDifficulty: 2,
    attackTechnique: "T1027"
  });
  variants.push({
    command: `powershell.exe -e ${b64}`,
    category: "encoding",
    description: "PowerShell -e (short flag) with Base64 payload",
    detected: false,
    evasionDifficulty: 2,
    attackTechnique: "T1027"
  });
  const hexCmd = command.split("").map((c) => {
    if (/[a-zA-Z]/.test(c) && Math.random() > 0.5) {
      return `\\x${c.charCodeAt(0).toString(16)}`;
    }
    return c;
  }).join("");
  if (hexCmd !== command) {
    variants.push({
      command: hexCmd,
      category: "encoding",
      description: "Partial hex encoding of alphabetic characters",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1027"
    });
  }
  const certutilB64 = Buffer.from(command).toString("base64");
  variants.push({
    command: `cmd.exe /c "echo ${certutilB64} > %TEMP%\\e.b64 && certutil -decode %TEMP%\\e.b64 %TEMP%\\e.bat && %TEMP%\\e.bat"`,
    category: "encoding",
    description: "Certutil Base64 decode to temp file then execute",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1140"
  });
  return variants;
}
function mutateCaretVariants(command) {
  const variants = [];
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
      attackTechnique: "T1027"
    });
  }
  const caretAll = command.split("").map((c, i) => {
    if (/[a-zA-Z]/.test(c) && i % 3 === 0) return "^" + c;
    return c;
  }).join("");
  if (caretAll !== command) {
    variants.push({
      command: caretAll,
      category: "caret",
      description: "Sparse caret insertion throughout command",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1027"
    });
  }
  const fullCaret = `cmd.exe /c "${command.split("").join("^")}"`;
  variants.push({
    command: fullCaret,
    category: "caret",
    description: "Full command wrapped in cmd /c with caret escaping",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003"
  });
  return variants;
}
function mutateVariableIndirection(command) {
  const variants = [];
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
      attackTechnique: "T1059.003"
    });
  }
  if (command.length <= 80) {
    const setStatements = command.split("").map((c, i) => `set c${i}=${c}`).join(" && ");
    const callParts = command.split("").map((_, i) => `%c${i}%`).join("");
    variants.push({
      command: `cmd.exe /c "${setStatements} && call ${callParts}"`,
      category: "variable_indirection",
      description: "Character-by-character variable construction",
      detected: false,
      evasionDifficulty: 4,
      attackTechnique: "T1059.003"
    });
  }
  variants.push({
    command: `cmd.exe /c "for /f "tokens=*" %a in ('${command}') do @echo %a"`,
    category: "variable_indirection",
    description: "Command executed inside FOR /F loop",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003"
  });
  return variants;
}
function mutateInterpreterChain(command) {
  const variants = [];
  const isCmd = command.toLowerCase().startsWith("cmd") || !command.toLowerCase().startsWith("powershell");
  const isPowershell = command.toLowerCase().startsWith("powershell");
  if (isCmd && !isPowershell) {
    variants.push({
      command: `powershell.exe -NoProfile -Command "& { ${command.replace(/"/g, '`"')} }"`,
      category: "interpreter_chain",
      description: "cmd command wrapped in PowerShell execution",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1059.001"
    });
    variants.push({
      command: `wmic process call create "${command}"`,
      category: "interpreter_chain",
      description: "Command executed via WMIC process create",
      detected: false,
      evasionDifficulty: 3,
      attackTechnique: "T1047"
    });
  }
  if (isPowershell) {
    variants.push({
      command: `cmd.exe /c "${command}"`,
      category: "interpreter_chain",
      description: "PowerShell command wrapped in cmd.exe",
      detected: false,
      evasionDifficulty: 2,
      attackTechnique: "T1059.003"
    });
  }
  variants.push({
    command: `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""${command.replace(/"/g, '""')}"", 0:close")`,
    category: "interpreter_chain",
    description: "Command executed via mshta VBScript",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1218.005"
  });
  variants.push({
    command: `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("${command}")`,
    category: "interpreter_chain",
    description: "Command executed via rundll32 JavaScript",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1218.011"
  });
  return variants;
}
function mutateArgumentReorder(command) {
  const variants = [];
  const parts = command.split(/\s+/);
  if (parts.length < 3) return variants;
  const exe = parts[0];
  const args = parts.slice(1);
  const reversed = [exe, ...args.reverse()].join(" ");
  if (reversed !== command) {
    variants.push({
      command: reversed,
      category: "argument_reorder",
      description: "Arguments reversed in order",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1036"
    });
  }
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
        attackTechnique: "T1036"
      });
    }
  }
  return variants;
}
function mutateWhitespace(command) {
  const variants = [];
  const extraSpaces = command.replace(/\s+/g, "    ");
  if (extraSpaces !== command) {
    variants.push({
      command: extraSpaces,
      category: "whitespace",
      description: "Extra spaces between tokens",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027"
    });
  }
  const tabs = command.replace(/\s+/g, "	");
  if (tabs !== command) {
    variants.push({
      command: tabs,
      category: "whitespace",
      description: "Tab characters as delimiters",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027"
    });
  }
  const mixed = command.replace(/\s+/g, " 	 ");
  if (mixed !== command) {
    variants.push({
      command: mixed,
      category: "whitespace",
      description: "Mixed spaces and tabs as delimiters",
      detected: false,
      evasionDifficulty: 1,
      attackTechnique: "T1027"
    });
  }
  return variants;
}
function mutateStringConcat(command) {
  const variants = [];
  const mid = Math.floor(command.length / 2);
  const part1 = command.substring(0, mid);
  const part2 = command.substring(mid);
  variants.push({
    command: `powershell.exe -NoProfile -Command "& { $a='${part1.replace(/'/g, "''")}'; $b='${part2.replace(/'/g, "''")}'; Invoke-Expression ($a+$b) }"`,
    category: "string_concat",
    description: "Command split and concatenated via PowerShell variables",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1027"
  });
  variants.push({
    command: `cmd.exe /c "set a=${part1}&& set b=${part2}&& call %a%%b%"`,
    category: "string_concat",
    description: "Command split and concatenated via cmd SET variables",
    detected: false,
    evasionDifficulty: 3,
    attackTechnique: "T1059.003"
  });
  const charArray = command.split("").map((c) => c.charCodeAt(0)).join(",");
  variants.push({
    command: `powershell.exe -NoProfile -Command "& { IEX([char[]](${charArray}) -join '') }"`,
    category: "string_concat",
    description: "Command built from char code array via -join",
    detected: false,
    evasionDifficulty: 4,
    attackTechnique: "T1027"
  });
  return variants;
}
function parseSigmaRule(yamlContent) {
  const lines = yamlContent.split("\n");
  const rule = {
    title: "",
    detectionPatterns: [],
    logSource: {},
    attackTags: [],
    level: "medium"
  };
  let inDetection = false;
  let inSelection = false;
  let inLogSource = false;
  let currentField = "";
  let currentModifier = "";
  let currentValues = [];
  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();
    if (line.startsWith("title:")) {
      rule.title = line.substring(6).trim().replace(/^['"]|['"]$/g, "");
    } else if (line.startsWith("id:")) {
      rule.id = line.substring(3).trim();
    } else if (line.startsWith("description:")) {
      rule.description = line.substring(12).trim().replace(/^['"]|['"]$/g, "");
    } else if (line.startsWith("level:")) {
      const lvl = line.substring(6).trim().toLowerCase();
      if (["informational", "low", "medium", "high", "critical"].includes(lvl)) {
        rule.level = lvl;
      }
    } else if (line.startsWith("tags:")) {
    } else if (trimmed.startsWith("- attack.")) {
      rule.attackTags.push(trimmed.substring(2));
    }
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
    if (line.startsWith("detection:")) {
      inDetection = true;
      inLogSource = false;
      inSelection = false;
      continue;
    }
    if (inDetection) {
      if (/^\s{4}\w/.test(line) && trimmed.includes(":") && !trimmed.startsWith("-")) {
        if (currentField && currentValues.length > 0) {
          rule.detectionPatterns.push({
            field: currentField,
            values: [...currentValues],
            caseInsensitive: true,
            modifier: currentModifier || void 0
          });
        }
        const colonIdx = trimmed.indexOf(":");
        const fieldPart = trimmed.substring(0, colonIdx).trim();
        const valuePart = trimmed.substring(colonIdx + 1).trim();
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
        currentValues.push(trimmed.substring(2).replace(/^['"]|['"]$/g, ""));
      } else if (trimmed.startsWith("condition:")) {
        if (currentField && currentValues.length > 0) {
          rule.detectionPatterns.push({
            field: currentField,
            values: [...currentValues],
            caseInsensitive: true,
            modifier: currentModifier || void 0
          });
        }
        inSelection = false;
      }
      if (!line.startsWith(" ") && line.length > 0 && !line.startsWith("detection:")) {
        inDetection = false;
      }
    }
  }
  if (currentField && currentValues.length > 0) {
    rule.detectionPatterns.push({
      field: currentField,
      values: [...currentValues],
      caseInsensitive: true,
      modifier: currentModifier || void 0
    });
  }
  return rule;
}
function matchesDetectionPattern(command, pattern) {
  const cmdLower = pattern.caseInsensitive ? command.toLowerCase() : command;
  for (const value of pattern.values) {
    const valLower = pattern.caseInsensitive ? value.toLowerCase() : value;
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
        }
        break;
      default:
        if (hasWildcard) {
          const regexStr = "^" + valLower.replace(/\*/g, ".*") + "$";
          try {
            if (new RegExp(regexStr, "i").test(command)) return true;
          } catch {
          }
        } else {
          if (cmdLower.includes(valLower)) return true;
        }
    }
  }
  return false;
}
function matchesSigmaRule(command, rule) {
  if (rule.detectionPatterns.length === 0) return false;
  const cmdFields = rule.detectionPatterns.filter(
    (p) => [
      "CommandLine",
      "commandline",
      "command_line",
      "ParentCommandLine",
      "OriginalFileName",
      "Image",
      "ParentImage",
      "TargetFilename",
      "ProcessName"
    ].includes(p.field) || p.field === "selection"
  );
  if (cmdFields.length === 0) {
    return rule.detectionPatterns.some(
      (p) => matchesDetectionPattern(command, p)
    );
  }
  return cmdFields.some((p) => matchesDetectionPattern(command, p));
}
function matchesRawPattern(command, pattern) {
  try {
    if (new RegExp(pattern, "i").test(command)) return true;
  } catch {
  }
  if (command.toLowerCase().includes(pattern.toLowerCase())) return true;
  return false;
}
function generateMutations(command, options) {
  const categories = options?.categories || ALL_CATEGORIES;
  const maxPerCat = options?.maxPerCategory || 3;
  const dedup = options?.deduplicate !== false;
  const allVariants = [];
  const generators = {
    case: mutateCaseVariants,
    path: mutatePathVariants,
    env_var: mutateEnvVarVariants,
    encoding: mutateEncodingVariants,
    caret: mutateCaretVariants,
    variable_indirection: mutateVariableIndirection,
    interpreter_chain: mutateInterpreterChain,
    argument_reorder: mutateArgumentReorder,
    whitespace: mutateWhitespace,
    string_concat: mutateStringConcat
  };
  for (const cat of categories) {
    const gen = generators[cat];
    if (!gen) continue;
    const variants = gen(command).slice(0, maxPerCat);
    allVariants.push(...variants);
  }
  if (dedup) {
    const seen = /* @__PURE__ */ new Set();
    return allVariants.filter((v) => {
      if (seen.has(v.command)) return false;
      seen.add(v.command);
      return true;
    });
  }
  return allVariants;
}
function testRuleMutations(command, sigmaRule, options) {
  const variants = generateMutations(command, options);
  for (const variant of variants) {
    variant.detected = matchesSigmaRule(variant.command, sigmaRule);
  }
  const detectedCount = variants.filter((v) => v.detected).length;
  const evadedCount = variants.filter((v) => !v.detected).length;
  const totalVariants = variants.length;
  const robustnessScore = totalVariants > 0 ? Math.round(detectedCount / totalVariants * 100) : 100;
  let robustnessClass;
  if (robustnessScore >= 80) robustnessClass = "robust";
  else if (robustnessScore >= 50) robustnessClass = "moderate";
  else if (robustnessScore >= 20) robustnessClass = "fragile";
  else robustnessClass = "bypassed";
  const categoryStats = /* @__PURE__ */ new Map();
  for (const v of variants) {
    const stat = categoryStats.get(v.category) || { total: 0, evaded: 0 };
    stat.total++;
    if (!v.detected) stat.evaded++;
    categoryStats.set(v.category, stat);
  }
  const weakestCategories = [];
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
  const hardeningTips = generateHardeningTips(weakestCategories, sigmaRule);
  const patternStr = sigmaRule.detectionPatterns.map((p) => `${p.field}${p.modifier ? "|" + p.modifier : ""}: ${p.values.join(", ")}`).join(" AND ");
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
    hardeningTips
  };
}
function testRawPatternMutations(command, pattern, options) {
  const variants = generateMutations(command, options);
  for (const variant of variants) {
    variant.detected = matchesRawPattern(variant.command, pattern);
  }
  const detectedCount = variants.filter((v) => v.detected).length;
  const evadedCount = variants.filter((v) => !v.detected).length;
  const totalVariants = variants.length;
  const robustnessScore = totalVariants > 0 ? Math.round(detectedCount / totalVariants * 100) : 100;
  let robustnessClass;
  if (robustnessScore >= 80) robustnessClass = "robust";
  else if (robustnessScore >= 50) robustnessClass = "moderate";
  else if (robustnessScore >= 20) robustnessClass = "fragile";
  else robustnessClass = "bypassed";
  const categoryStats = /* @__PURE__ */ new Map();
  for (const v of variants) {
    const stat = categoryStats.get(v.category) || { total: 0, evaded: 0 };
    stat.total++;
    if (!v.detected) stat.evaded++;
    categoryStats.set(v.category, stat);
  }
  const weakestCategories = [];
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
    hardeningTips
  };
}
function generateHardeningTips(weakCategories, rule) {
  const tips = [];
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
function generateHardeningTipsFromCategories(weakCategories) {
  return generateHardeningTips(weakCategories, {
    title: "",
    detectionPatterns: [],
    logSource: {},
    attackTags: [],
    level: "medium"
  });
}
var ALL_CATEGORIES = [
  "case",
  "path",
  "env_var",
  "encoding",
  "caret",
  "variable_indirection",
  "interpreter_chain",
  "argument_reorder",
  "whitespace",
  "string_concat"
];
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export {
  parseSigmaRule,
  generateMutations,
  testRuleMutations,
  testRawPatternMutations
};
